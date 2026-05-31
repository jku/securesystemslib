import unittest
from unittest.mock import ANY, MagicMock, patch
from urllib import parse

from securesystemslib.signer import SSlibKey
from securesystemslib.signer._tkey_signer import (
    PROTO_DATA_LENGTH,
    Endpoint,
    LenIdx,
    Rsp,
    TKeyError,
    TKeySigner,
    _TKey,
)


def make_response_frame(  # noqa: PLR0913
    fid: int,
    eid: int,
    status: int,
    len_idx: int,
    resp_id: int,
    data: bytes = b"",
) -> bytes:
    header = (fid << 5) | (eid << 3) | (status << 2) | len_idx
    resp_len = PROTO_DATA_LENGTH[len_idx]
    resp_data = bytearray(resp_len)
    resp_data[0] = resp_id
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

    def test_from_priv_key_uri_parsing(self) -> None:
        # 1. Default version (4) and no uss
        signer = TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0", self.mock_public_key)
        self.assertEqual(signer.device_path, "/dev/ttyACM0")
        self.assertEqual(signer.version, 4)
        self.assertFalse(signer.use_uss)

        # 2. Custom version
        signer = TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0?version=5", self.mock_public_key)
        self.assertEqual(signer.device_path, "/dev/ttyACM0")
        self.assertEqual(signer.version, 5)

        # 3. No path, custom version
        signer = TKeySigner.from_priv_key_uri("tkey:?version=12", self.mock_public_key)
        self.assertIsNone(signer.device_path)
        self.assertEqual(signer.version, 12)

        # 4. Invalid version format
        with self.assertRaises(ValueError):
            TKeySigner.from_priv_key_uri("tkey:?version=invalid", self.mock_public_key)

        # 5. Parsing use_uss
        signer = TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0?use_uss=true", self.mock_public_key)
        self.assertTrue(signer.use_uss)

        signer = TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0?use_uss=false", self.mock_public_key)
        self.assertFalse(signer.use_uss)

        signer = TKeySigner.from_priv_key_uri("tkey:/dev/ttyACM0?version=5&use_uss=true", self.mock_public_key)
        self.assertEqual(signer.version, 5)
        self.assertTrue(signer.use_uss)

    @patch("securesystemslib.signer._tkey_signer._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(_TKey, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    @patch.object(_TKey, "list_devices", return_value=["/dev/ttyACM0"])
    def test_import_with_app_already_loaded(
        self,
        mock_list_devices: MagicMock,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Prepare connection mock (needs enough reads for two sequential import calls)
        app_name_payload = b"tk1 " + b"mlds" + (4).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=Endpoint.APP,
            status=0,
            len_idx=LenIdx.I32,
            resp_id=Rsp.GET_NAME_VER_APP,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response, b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(_TKey, "_load_app") as mock_load_app:
            # 1. Explicit path
            uri, key = TKeySigner.import_("/dev/ttyACM0", version=4)
            self.assertEqual(uri, "tkey:/dev/ttyACM0?version=4")
            self.assertEqual(key, mock_key)

            # 2. Auto-detect path
            uri, key = TKeySigner.import_(version=4)
            self.assertEqual(uri, "tkey:?version=4")
            self.assertEqual(key, mock_key)

            mock_load_app.assert_not_called()

    @patch("securesystemslib.signer._tkey_signer._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(_TKey, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    def test_import_with_app_loaded_mismatched_version(
        self,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Setup serial response: GET_NAME_VER_APP returns version 4
        app_name_payload = b"tk1 " + b"mlds" + (4).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=Endpoint.APP,
            status=0,
            len_idx=LenIdx.I32,
            resp_id=Rsp.GET_NAME_VER_APP,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response])
        mock_conn_class.return_value = mock_conn

        # Request version 5, which is running version 4. Should raise TKeyError.
        with self.assertRaises(TKeyError) as ctx:
            TKeySigner.import_("/dev/ttyACM0", version=5)
        self.assertIn("unknown application", str(ctx.exception))

    @patch("securesystemslib.signer._tkey_signer._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(_TKey, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    def test_import_in_firmware_mode_loads_correct_version(
        self,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=Endpoint.FW,
            status=0,
            len_idx=LenIdx.I32,
            resp_id=Rsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        # Mock keys
        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(_TKey, "_load_app") as mock_load_app:
            uri, key = TKeySigner.import_("/dev/ttyACM0", version=5)
            self.assertEqual(uri, "tkey:/dev/ttyACM0?version=5")
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called
            mock_load_app.assert_called_once()
            # Verify self.app_resource path ends with app_v5.bin
            self.assertTrue(mock_load_app.call_args[0][0].endswith("app_v5.bin"))

    @patch("securesystemslib.signer._tkey_signer._RawSerialConnection")
    @patch("securesystemslib.signer._tkey_signer.MLDSA44PublicKey.from_public_bytes")
    @patch("securesystemslib.signer._tkey_signer.SSlibKey.from_crypto")
    @patch.object(_TKey, "get_pubkey", return_value=b"dummy_pubkey_bytes")
    def test_import_with_uss(
        self,
        mock_get_pubkey: MagicMock,
        mock_from_crypto: MagicMock,
        mock_from_public_bytes: MagicMock,
        mock_conn_class: MagicMock,
    ) -> None:
        # Setup serial response: NAME_VERSION FW command succeeds
        fw_name_payload = b"tk1 " + b"mkdf"
        fw_response = make_response_frame(
            fid=1,
            eid=Endpoint.FW,
            status=0,
            len_idx=LenIdx.I32,
            resp_id=Rsp.NAME_VERSION,
            data=fw_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[fw_response])
        mock_conn_class.return_value = mock_conn

        mock_key = MagicMock(spec=SSlibKey)
        mock_from_crypto.return_value = mock_key

        with patch.object(_TKey, "_load_app") as mock_load_app:
            uri, key = TKeySigner.import_("/dev/ttyACM0", version=4, uss="mysecret")
            parsed = parse.urlparse(uri)
            query = parse.parse_qs(parsed.query)
            self.assertEqual(query.get("version"), ["4"])
            self.assertEqual(query.get("use_uss"), ["true"])
            self.assertEqual(key, mock_key)

            # Verify that _load_app was called with secret
            mock_load_app.assert_called_once_with(ANY, secret="mysecret")

    @patch("securesystemslib.signer._tkey_signer._RawSerialConnection")
    def test_sign_with_uss(self, mock_conn_class: MagicMock) -> None:
        # Mock connection so connect doesn't reload the app (app already loaded)
        app_name_payload = b"tk1 " + b"mlds" + (4).to_bytes(4, byteorder="little")
        app_response = make_response_frame(
            fid=2,
            eid=Endpoint.APP,
            status=0,
            len_idx=LenIdx.I32,
            resp_id=Rsp.GET_NAME_VER_APP,
            data=app_name_payload,
        )
        mock_conn = MockStreamConnection(reads=[b"", app_response])
        mock_conn_class.return_value = mock_conn

        secrets_handler = MagicMock(return_value="mysecret")
        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            version=4,
            public_key=self.mock_public_key,
            secrets_handler=secrets_handler,
            use_uss=True,
        )

        with patch("securesystemslib.signer._tkey_signer._TKey") as mock_tkey_class:
            mock_tk_inst = MagicMock()
            mock_tk_inst.sign.return_value = b"dummy_signature"
            mock_tk_inst.__enter__.return_value = mock_tk_inst
            mock_tkey_class.return_value = mock_tk_inst

            signature = signer.sign(b"mypayload")
            self.assertEqual(signature.keyid, "mock_keyid")
            self.assertEqual(signature.signature, b"dummy_signature".hex())

            # secrets_handler should have been called with "uss"
            secrets_handler.assert_called_once_with("User Supplied Secret")
            # _TKey constructor should have been called with secret="mysecret"
            mock_tkey_class.assert_called_once_with("/dev/ttyACM0", 4, secret="mysecret")

    def test_sign_with_uss_missing_secrets_handler(self) -> None:
        signer = TKeySigner(
            device_path="/dev/ttyACM0",
            version=4,
            public_key=self.mock_public_key,
            secrets_handler=None,
            use_uss=True,
        )
        with self.assertRaises(ValueError) as ctx:
            signer.sign(b"mypayload")
        self.assertIn("requires a secrets handler", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
