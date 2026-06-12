import hashlib
import unittest
from unittest.mock import MagicMock, patch
from urllib import parse

from securesystemslib.signer import SSlibKey, TKeySigner
from securesystemslib.signer._tkey.tkey import (
    PROTO_DATA_LENGTH,
    FwCmd,
    FwRsp,
    LenIdx,
    TKey,
    TKeyError,
    Rsp,
)
from securesystemslib.signer._tkey.tkey_mldsa import (
    MldsaRsp,
    TKeyMldsa,
)

ENDPOINT_FW = 2
ENDPOINT_APP = 3


def make_response_frame(  # noqa: PLR0913
    fid: int,
    eid: int,
    status: int,
    rsp: Rsp,
    data: bytes = b"",
) -> bytes:
    header = (fid << 5) | (eid << 3) | (status << 2) | rsp.len_idx
    resp_len = PROTO_DATA_LENGTH[rsp.len_idx]
    resp_data = bytearray(resp_len)
    resp_data[0] = rsp.id
    if data:
        resp_data[1 : 1 + len(data)] = data
    return bytes([header]) + bytes(resp_data)


class MockStreamConnection:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = reads
        self.written = bytearray()
        self.timeout = 5.0

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data)

    def read(self, n: int) -> bytes:
        if not self.reads:
            return b""
        block = self.reads[0]
        chunk = block[:n]
        if len(chunk) == len(block):
            self.reads.pop(0)
        else:
            self.reads[0] = block[n:]
        return chunk

    def close(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        return sum(len(b) for b in self.reads)


class TestTKeySignerOffline(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_public_key = MagicMock(spec=SSlibKey)
        self.mock_public_key.scheme = "ml-dsa-44/1"
        self.mock_public_key.keyid = "mock_keyid"
        self.mock_public_key.keyval = {"public": "mock_pubkey_pem"}

    @patch("securesystemslib.signer._tkey_signer.TKeyMldsa")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySigner, "_get_app")
    def test_from_priv_key_uri_parsing(
        self,
        mock_get_app: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        # path and version
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?version=5", self.mock_public_key
        )
        mock_tkey_class.assert_called_with("/dev/ttyACM0", b"dummy_binary", 5, None)

        # version only
        TKeySigner.from_priv_key_uri("tkey:?version=12", self.mock_public_key)
        mock_tkey_class.assert_called_with(None, b"dummy_binary", 12, None)

        # No version
        with self.assertRaises(ValueError):
            TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0", self.mock_public_key)

        # Invalid version format
        with self.assertRaises(ValueError):
            TKeySigner.from_priv_key_uri("tkey:?version=invalid", self.mock_public_key)

        # passphrase=true without secrets_handler should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            TKeySigner.from_priv_key_uri(
                "tkey:/dev/ttyACM0?version=5&passphrase=true",
                self.mock_public_key,
            )
        self.assertIn("no secrets_handler was given", str(ctx.exception))

        # passphrase=true with secrets_handler
        secrets_handler = MagicMock(return_value="mysecret")
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?version=5&passphrase=true",
            self.mock_public_key,
            secrets_handler,
        )
        secrets_handler.assert_called_once_with("Passphrase")
        mock_tkey_class.assert_called_with(
            "/dev/ttyACM0", b"dummy_binary", 5, "mysecret"
        )

        # passphrase=false
        mock_tkey_class.reset_mock()
        secrets_handler.reset_mock()
        TKeySigner.from_priv_key_uri(
            "tkey:/dev/ttyACM0?version=5&passphrase=false",
            self.mock_public_key,
            secrets_handler,
        )
        secrets_handler.assert_not_called()
        mock_tkey_class.assert_called_with("/dev/ttyACM0", b"dummy_binary", 5, None)

    @patch("securesystemslib.signer._tkey.tkey._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeyMldsa, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(TKeyMldsa, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeySigner, "_get_app")
    def test_import_with_app_already_loaded(  # noqa: PLR0913
        self,
        mock_get_app: MagicMock,
        mock_find_device: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        # Prepare connection mock (needs enough reads for two sequential import calls)
        app_name_payload = b"tk1 " + b"mlds" + (4).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=ENDPOINT_APP,
            status=0,
            rsp=MldsaRsp.GET_NAME_VER_APP,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response, b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            # 1. Explicit path
            uri, key = TKeySigner.import_("/dev/ttyACM0", version=4)
            self.assertEqual(uri, "tkey:/dev/ttyACM0?version=4")
            self.assertEqual(key, mock_key)

            mock_load_app.assert_called_with(b"dummy_binary", None)

            # 2. Auto-detect path
            uri, key = TKeySigner.import_(version=4)
            self.assertEqual(uri, "tkey:?version=4")
            self.assertEqual(key, mock_key)

            mock_load_app.assert_called_with(b"dummy_binary", None)

    @patch("securesystemslib.signer._tkey.tkey._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeyMldsa, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeyMldsa, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(TKeySigner, "_get_app")
    def test_import_with_app_loaded_mismatched_version(  # noqa: PLR0913
        self,
        mock_get_app: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        # Setup serial response: GET_NAME_VER_APP returns version 4
        app_name_payload = b"tk1 " + b"mlds" + (4).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=ENDPOINT_APP,
            status=0,
            rsp=MldsaRsp.GET_NAME_VER_APP,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Request version 5, which is running version 4. Should raise TKeyError.
        with self.assertRaises(TKeyError) as ctx:
            TKeySigner.import_("/dev/ttyACM0", version=5)
        self.assertIn("unknown application", str(ctx.exception))

    @patch("securesystemslib.signer._tkey.tkey._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeyMldsa, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeyMldsa, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(TKeySigner, "_get_app")
    def test_import_in_firmware_mode_loads_correct_version(  # noqa: PLR0913
        self,
        mock_get_app: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=ENDPOINT_FW,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            uri, key = TKeySigner.import_("/dev/ttyACM0", version=5)
            self.assertEqual(uri, "tkey:/dev/ttyACM0?version=5")
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called with the dummy_binary
            mock_load_app.assert_called_once_with(b"dummy_binary", None)

    @patch("securesystemslib.signer._tkey.tkey._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeyMldsa, "_find_device", return_value="/dev/ttyACM0")
    @patch.object(TKeyMldsa, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(TKeySigner, "_get_app")
    def test_import_with_passphrase(  # noqa: PLR0913
        self,
        mock_get_app: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_find_device: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=ENDPOINT_FW,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(TKey, "load_app") as mock_load_app:
            uri, key = TKeySigner.import_(
                "/dev/ttyACM0", version=4, passphrase="mysecret"
            )
            parsed = parse.urlparse(uri)
            query = parse.parse_qs(parsed.query)
            self.assertEqual(query.get("version"), ["4"])
            self.assertEqual(query.get("passphrase"), ["true"])
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called with secret and dummy_binary
            mock_load_app.assert_called_once_with(b"dummy_binary", "mysecret")

    @patch("securesystemslib.signer._tkey.tkey._RawSerialConnection")
    @patch.object(TKeyMldsa, "_find_device", return_value="/dev/ttyACM0")
    def test_load_app_hashes_secret(
        self,
        mock_find_device: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Set up responses for:
        # 1. NAME_VERSION (FW mode check)
        # 2. LOAD_APP
        # 3. LOAD_APP_DATA (only one chunk because file size is small)
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=ENDPOINT_FW,
            status=0,
            rsp=FwRsp.NAME_VERSION,
            data=fw_name_payload,
        )

        load_app_response = make_response_frame(
            fid=2,
            eid=ENDPOINT_FW,
            status=0,
            rsp=FwRsp.LOAD_APP,
            data=b"\x00",
        )

        file_digest = hashlib.blake2s(b"mock_app_data", digest_size=32).digest()
        load_app_data_response = make_response_frame(
            fid=3,
            eid=ENDPOINT_FW,
            status=0,
            rsp=FwRsp.LOAD_APP_DATA_READY,
            data=b"\x00" + file_digest,
        )

        mock_conn = MockStreamConnection(
            reads=[fw_response, load_app_response, load_app_data_response]
        )
        mock_conn_class.return_value = mock_conn

        secret = "my_super_secret_passphrase"
        # We instantiate _TKey which should call _ensure_app_loaded -> _load_app
        tk = TKeyMldsa(device=None, binary=b"mock_app_data", version=4, secret=secret)
        tk.disconnect()

        # Now, let's inspect the written data for the LOAD_APP command.
        written_bytes = bytes(mock_conn.written)

        # First frame (NAME_VERSION): header + 1 byte data (FwCmd.NAME_VERSION) -> PROTO_DATA_LENGTH[0] is 1.
        # So total frame size: 1 + 1 = 2 bytes.
        # Second frame (LOAD_APP): header + 128 bytes (FwCmd.LOAD_APP + 127 bytes payload).
        # PROTO_DATA_LENGTH[3] is 128.
        # So total frame size: 1 + 128 = 129 bytes.
        # Let's extract this frame: it starts at index 2, length 129.
        load_app_frame = written_bytes[2 : 2 + 129]

        self.assertEqual(load_app_frame[0], 0x53)
        self.assertEqual(load_app_frame[1], FwCmd.LOAD_APP.id)

        # Let's check the data payload.
        expected_hashed_secret = hashlib.blake2s(
            secret.encode("utf-8"), digest_size=32
        ).digest()

        payload = load_app_frame[2:]
        self.assertEqual(payload[0:4], (13).to_bytes(4, byteorder="little"))
        self.assertEqual(payload[4], 1)
        self.assertEqual(payload[5 : 5 + 32], expected_hashed_secret)

    @patch("securesystemslib.signer._tkey_signer.TKeyMldsa")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySigner, "_get_app")
    def test_sign_with_passphrase(
        self,
        mock_get_app: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tk_inst.sign.return_value = b"dummy_signature"
        mock_tkey_class.return_value = mock_tk_inst

        secrets_handler = MagicMock(return_value="mysecret")
        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            version=4,
            public_key=self.mock_public_key,
            secrets_handler=secrets_handler,
        )

        signature = signer.sign(b"mypayload")
        self.assertEqual(signature.keyid, "mock_keyid")
        self.assertEqual(signature.signature, b"dummy_signature".hex())

        # secrets_handler should have been called with "uss" during construction
        secrets_handler.assert_called_once_with("Passphrase")
        # _TKey constructor should have been called with secret "mysecret" and expected app
        mock_tkey_class.assert_called_once_with(
            "/dev/ttyACM0", b"dummy_binary", 4, "mysecret"
        )

        # _TKey.sign should have been called with expected tuf formatted message
        digest = hashlib.sha512(b"mypayload").digest()
        expected_msg = b"tuf" + bytes([1]) + digest
        mock_tk_inst.sign.assert_called_once_with(expected_msg)

    @patch("securesystemslib.signer._tkey_signer.TKeyMldsa")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySigner, "_get_app")
    def test_sign_without_passphrase(
        self,
        mock_get_app: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        mock_key = MagicMock(spec=SSlibKey)
        mock_key.keyval = self.mock_public_key.keyval
        mock_from_crypto.return_value = mock_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tk_inst.sign.return_value = b"dummy_signature"
        mock_tkey_class.return_value = mock_tk_inst

        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            version=4,
            public_key=self.mock_public_key,
        )

        signature = signer.sign(b"mypayload")
        self.assertEqual(signature.keyid, "mock_keyid")
        self.assertEqual(signature.signature, b"dummy_signature".hex())

        # _TKey constructor should have been called with secret=None and expected app
        mock_tkey_class.assert_called_once_with(
            "/dev/ttyACM0", b"dummy_binary", 4, None
        )

    @patch("securesystemslib.signer._tkey_signer.TKeyMldsa")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(TKeySigner, "_get_app")
    def test_init_public_key_mismatch(
        self,
        mock_get_app: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_tkey_class: MagicMock,
    ) -> None:
        mock_get_app.side_effect = lambda version: b"dummy_binary"
        # Mock the derived key to have a mismatched keyval
        mock_derived_key = MagicMock(spec=SSlibKey)
        mock_derived_key.keyval = "mismatched_keyval"
        mock_from_crypto.return_value = mock_derived_key

        mock_tk_inst = MagicMock()
        mock_tk_inst.app_version = None
        mock_tk_inst.get_pubkey.return_value = b"dummy_pubkey_bytes"
        mock_tkey_class.return_value = mock_tk_inst

        # The signer public key has a different keyval
        self.mock_public_key.keyval = "expected_keyval"

        with self.assertRaises(RuntimeError) as ctx:
            TKeySigner(
                device_path="/dev/ttyACM0",
                version=4,
                public_key=self.mock_public_key,
            )
        self.assertIn("TKey public key does not match", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
