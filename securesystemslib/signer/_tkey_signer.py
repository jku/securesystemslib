"""ML-DSA-44 Signer for Tillitis TKey"""

from __future__ import annotations

import hashlib
import logging
import os
import select
import sys
from importlib.resources import as_file, files
from types import TracebackType
from typing import Protocol
from urllib import parse

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from securesystemslib.exceptions import Error, UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

# Linux-specific stdlib modules
LINUX_IMPORT_ERROR = None
try:
    import array
    import fcntl
    import termios
except ImportError:
    LINUX_IMPORT_ERROR = "linux modules only needed on linux"

PYSERIAL_IMPORT_ERROR = None
try:
    import serial  # type: ignore[import-untyped]
    from serial.tools import list_ports  # type: ignore[import-untyped]
except ImportError:
    PYSERIAL_IMPORT_ERROR = "pyserial is require for TKeySigner"


logger = logging.getLogger(__name__)

# USB Vendor & Product ID for TKey
TKEY_USB_VID = 0x1207
TKEY_USB_PID = 0x8887

# Maximum size for applications to load onto TKey (100 KiB)
APP_MAXSIZE = 100 * 1024

# Protocol chunking
CHUNK_SIZE = 120
SIG_SIZE = 2420
KEY_SIZE = 1312
SIG_CHUNKS = SIG_SIZE // CHUNK_SIZE
KEY_CHUNKS = KEY_SIZE // CHUNK_SIZE


class TKeyError(Error):
    """Base class for TKey errors."""


class TKeyIOError(TKeyError):
    """Raised when read/write fails."""


class TKeyProtocolError(TKeyError):
    """Raised upon protocol errors in command or response."""


class _SerialConnection(Protocol):
    timeout: float

    def read(self, n: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...

    @property
    def in_waiting(self) -> int: ...


# Protocol Endpoints
class Endpoint:
    FW = 2
    APP = 3


class Cmd:
    # FW commands:
    NAME_VERSION = 0x01
    LOAD_APP = 0x03
    LOAD_APP_DATA = 0x05
    # App commands:
    SET_SIZE = 0x03
    SIGN_DATA = 0x05
    GET_SIG = 0x07
    GET_KEY_CHUNK = 0x11
    GET_SIG_CHUNK = 0x13
    GET_NAME_VER_APP = 0x09


class Rsp:
    # FW Responses:
    NAME_VERSION = 0x02
    LOAD_APP = 0x04
    LOAD_APP_DATA = 0x06
    LOAD_APP_DATA_READY = 0x07
    # App Responses:
    SET_SIZE = 0x04
    SIGN_DATA = 0x06
    GET_SIG = 0x08
    GET_KEY_CHUNK = 0x12
    GET_SIG_CHUNK = 0x14
    GET_NAME_VER_APP = 0x0A


# Data lengths corresponding to header length bits (0, 1, 2, 3)
PROTO_DATA_LENGTH = [1, 4, 32, 128]


# Length indices mapping to PROTO_DATA_LENGTH
class LenIdx:
    I1 = 0
    I4 = 1
    I32 = 2
    I128 = 3


class _RawSerialConnection:
    """A raw Python serial connection.

    This helper exists because pyserial just did not work with TKey
    on linux
    """

    def __init__(self, port: str, baudrate: int, timeout: float) -> None:
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.fd: int | None = self._open()

    def _open(self) -> int:
        fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            # 1. Use termios to configure raw 8N1 mode
            attrs = termios.tcgetattr(fd)

            # Clear input processing
            attrs[0] &= ~(
                termios.IGNBRK
                | termios.BRKINT
                | termios.PARMRK
                | termios.ISTRIP
                | termios.INLCR
                | termios.IGNCR
                | termios.ICRNL
                | termios.IXON
                | termios.IXOFF
                | termios.IXANY
                | termios.INPCK
            )
            # Clear output processing (raw output)
            attrs[1] &= ~termios.OPOST
            # Clear local modes (no echo, no signals, no canonical input)
            attrs[3] &= ~(
                termios.ECHO
                | termios.ECHONL
                | termios.ICANON
                | termios.ISIG
                | termios.IEXTEN
            )
            # Clear control modes (no size, parity, stop bits, flow control)
            attrs[2] &= ~(
                termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS
            )
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL

            # Set speed using standard constants (this is changed below)
            attrs[4] = termios.B9600
            attrs[5] = termios.B9600

            termios.tcsetattr(fd, termios.TCSANOW, attrs)

            # 2. Use termios2 to set the custom 62500 baud rate
            tcgets2 = 0x802C542A
            tcsets2 = 0x402C542B
            bother = 0o010000

            buf = array.array("i", [0] * 64)
            fcntl.ioctl(fd, tcgets2, buf)

            buf[2] &= ~0x100F  # Clear CBAUD/CBAUDEX speed flags
            buf[2] |= bother  # Flag for custom speed (BOTHER)
            buf[9] = buf[10] = 62500  # Set custom speed

            fcntl.ioctl(fd, tcsets2, buf)

            # 3. Restore blocking mode
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

            # 4. Acquire exclusive access
            tiocexcl = 0x540C
            fcntl.ioctl(fd, tiocexcl, 0)

            return fd
        except Exception:
            os.close(fd)
            raise

    def write(self, data: bytes) -> int:
        if self.fd is None:
            raise ValueError("Port is closed")
        return os.write(self.fd, data)

    def read(self, n: int) -> bytes:
        """Read exactly n bytes blockingly, respecting the configured timeout."""
        if self.fd is None:
            raise ValueError("Port is closed")
        data = bytearray()
        while len(data) < n:
            r, _, _ = select.select([self.fd], [], [], self.timeout)
            if not r:
                break  # Timeout
            chunk = os.read(self.fd, n - len(data))
            if len(chunk) == 0:
                break  # EOF/Disconnect
            data.extend(chunk)
        return bytes(data)

    def reset_input_buffer(self) -> None:
        pass

    def reset_output_buffer(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        if self.fd is None:
            return 0
        buf = array.array("i", [0])
        try:
            fcntl.ioctl(self.fd, termios.FIONREAD, buf)
            return buf[0]
        except Exception:
            return 0

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _TKey:
    """Client for a TKey ML-DSA signer application"""

    def __init__(
        self,
        device: str,
        version: int,
        secret: str | None = None,
    ) -> None:
        if PYSERIAL_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYSERIAL_IMPORT_ERROR)

        self._port = device
        self._conn: _SerialConnection | None = None
        self._fid = 0
        self.version = version
        self.secret = secret
        self.app_resource = files("securesystemslib.signer.tkey").joinpath(
            f"app_v{version}.bin"
        )
        self.connect(baudrate=62500, timeout=5.0)

    def connect(self, baudrate: int, timeout: float) -> None:
        if sys.platform == "linux":
            self._conn = _RawSerialConnection(self._port, baudrate, timeout)
        else:
            try:
                self._conn = serial.Serial(
                    self._port, baudrate=baudrate, timeout=timeout
                )
            except Exception as e:
                raise TKeyError(f"Failed to open serial port {self._port}: {e}") from e
        self._ensure_app_loaded()

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception as e:
                logger.debug("Failed to close TKey connection: %s", e)
            self._conn = None

    def __enter__(self) -> _TKey:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    def _next_fid(self) -> int:
        """Returns a frame id (rotating sequence [0-3])"""
        self._fid = (self._fid + 1) % 4
        return self._fid

    @staticmethod
    def _validate_response(
        eid: int, cmd_id: int, resp_id: int, resp_len_idx: int
    ) -> None:
        """Validate response ID and length index matches expected response."""
        match (eid, cmd_id, resp_id, resp_len_idx):
            # Firmware Commands
            case (Endpoint.FW, Cmd.NAME_VERSION, Rsp.NAME_VERSION, LenIdx.I32):
                pass
            case (Endpoint.FW, Cmd.LOAD_APP, Rsp.LOAD_APP, LenIdx.I4):
                pass
            case (Endpoint.FW, Cmd.LOAD_APP_DATA, Rsp.LOAD_APP_DATA, LenIdx.I4):
                pass
            case (Endpoint.FW, Cmd.LOAD_APP_DATA, Rsp.LOAD_APP_DATA_READY, LenIdx.I128):
                pass

            # Application Commands
            case (Endpoint.APP, Cmd.GET_KEY_CHUNK, Rsp.GET_KEY_CHUNK, LenIdx.I128):
                pass
            case (Endpoint.APP, Cmd.SET_SIZE, Rsp.SET_SIZE, LenIdx.I4):
                pass
            case (Endpoint.APP, Cmd.SIGN_DATA, Rsp.SIGN_DATA, LenIdx.I4):
                pass
            case (Endpoint.APP, Cmd.GET_SIG, Rsp.GET_SIG, LenIdx.I128):
                pass
            case (Endpoint.APP, Cmd.GET_SIG_CHUNK, Rsp.GET_SIG_CHUNK, LenIdx.I128):
                pass
            case (Endpoint.APP, Cmd.GET_NAME_VER_APP, Rsp.GET_NAME_VER_APP, LenIdx.I32):
                pass
            case _:
                raise TKeyProtocolError(
                    f"Unexpected protocol response: endpoint={eid:#x}, cmd={cmd_id:#x},"
                    f" response={resp_id:#x}, len_index={resp_len_idx}"
                )

    def send(
        self,
        cmd_id: int,
        cmd_len_idx: int,
        eid: int,
        data: bytes = b"",
        timeout: int = -1,
    ) -> bytes:
        """Frame and send a command, then read and validate the response."""
        if self._conn is None:
            raise TKeyError("TKey is not connected")

        old_timeout = self._conn.timeout
        if timeout >= 0:
            self._conn.timeout = timeout
        try:
            return self._send(cmd_id, cmd_len_idx, eid, data)
        finally:
            if timeout >= 0:
                self._conn.timeout = old_timeout

    def _send(
        self,
        cmd_id: int,
        cmd_len_idx: int,
        eid: int,
        data: bytes = b"",
    ) -> bytes:
        if self._conn is None:
            raise TKeyError("TKey is not connected")

        fid = self._next_fid()

        expected_len = PROTO_DATA_LENGTH[cmd_len_idx]
        if len(data) > expected_len - 1:
            raise TKeyProtocolError("Data exceeds command data length in header")

        header = (fid << 5) | (eid << 3) | cmd_len_idx
        frame = bytearray(1 + expected_len)
        frame[0] = header
        frame[1] = cmd_id
        if data:
            frame[2 : 2 + len(data)] = data

        try:
            self._conn.write(bytes(frame))
        except Exception as e:
            raise TKeyIOError(f"Failed to write frame: {e}") from e

        try:
            resp_header_byte = self._conn.read(1)
        except Exception as e:
            raise TKeyIOError(f"Failed to read response header: {e}") from e

        if not resp_header_byte:
            raise TKeyIOError("No response data")

        header_val = resp_header_byte[0]
        resp_fid = (header_val >> 5) & 3
        resp_eid = (header_val >> 3) & 3
        resp_status = (header_val >> 2) & 3
        resp_len_idx = header_val & 3
        resp_len = PROTO_DATA_LENGTH[resp_len_idx]

        if resp_status == 1:
            try:
                self._conn.read(resp_len)
            except Exception as e:
                logger.debug("Failed to read remaining bytes after NOK status: %s", e)
            raise TKeyError("Response status code not OK (1)")

        try:
            resp_data = self._conn.read(resp_len)
        except Exception as e:
            raise TKeyIOError(f"Failed to read response data: {e}") from e

        if len(resp_data) != resp_len:
            raise TKeyProtocolError("Unexpected response data length")

        # Validate frame ID and endpoint
        if resp_fid != fid or resp_eid != eid:
            raise TKeyProtocolError(
                f"Response mismatch: expected Frame ID {fid} and Endpoint {eid}, "
                f"got Frame ID {resp_fid} and Endpoint {resp_eid}"
            )

        self._validate_response(resp_eid, cmd_id, resp_data[0], resp_len_idx)

        response = bytearray(1 + resp_len)
        response[0] = header_val
        response[1:] = resp_data
        return bytes(response)

    @classmethod
    def list_devices(cls) -> list[str]:
        """Discover TKey device paths using pyserial."""
        if PYSERIAL_IMPORT_ERROR:
            raise UnsupportedLibraryError(PYSERIAL_IMPORT_ERROR)

        devices = []
        for port in list_ports.comports():
            if port.vid == TKEY_USB_VID and port.pid == TKEY_USB_PID:
                devices.append(port.device)
        return sorted(devices)

    def _load_app(self, file_path: str, secret: str | None = None) -> None:
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            raise TKeyError(f"Failed to read app file {file_path}: {e}") from e

        if file_size > APP_MAXSIZE:
            raise TKeyError(f"File too big ({file_size} > {APP_MAXSIZE})")

        file_digest = hashlib.blake2s(file_data, digest_size=32).digest()

        # cmdLoadApp ID 0x03, length index 3 (128 bytes)
        data = bytearray(127)
        data[0:4] = file_size.to_bytes(4, byteorder="little")
        if secret is not None:
            data[4] = 1
            encoded_secret = secret.encode("utf-8")
            data[5 : 5 + len(encoded_secret)] = encoded_secret

        response = self.send(Cmd.LOAD_APP, 3, Endpoint.FW, bytes(data))
        if response[2] == 1:
            raise TKeyError("Device not ready (STATUS_BAD)")

        result_digest = self._load_app_data(file_data)
        if file_digest != result_digest:
            raise TKeyError(
                "Hash digests do not match "
                f"({file_digest.hex()} != {result_digest.hex()})"
            )

    def _load_app_data(self, file_data: bytes) -> bytes:
        # cmdLoadAppData ID 0x05, length index 3 (128 bytes)
        digest = b""
        offset = 0
        while offset < len(file_data):
            chunk = file_data[offset : offset + 127]
            response = self.send(Cmd.LOAD_APP_DATA, 3, Endpoint.FW, chunk)
            response_id = response[1]
            status = response[2]
            if status == 1:
                raise TKeyError("Bad status when writing app data")

            if response_id == Rsp.LOAD_APP_DATA_READY:
                digest = response[3:35]
            elif response_id != Rsp.LOAD_APP_DATA:
                raise TKeyProtocolError(f"Unexpected response code {response_id}")

            offset += 127

        return digest

    def _ensure_app_loaded(self) -> None:
        """Check if signer app is loaded on TKey, and load it in firmware mode."""
        # 1. Try to query firmware mode name and version
        try:
            rx = self.send(Cmd.NAME_VERSION, 0, Endpoint.FW)
            fw_name0 = rx[2:6].decode("ascii").rstrip()
            fw_name1 = rx[6:10].decode("ascii").rstrip()
            if fw_name0 != "tk1" or fw_name1 != "mkdf":
                raise TKeyError(
                    f"TKey is running an unknown firmware {fw_name0, fw_name1}"
                )
        except TKeyError:
            # The running application rejected the firmware command, or timed out
            # Query application name and version
            rx = self.send(Cmd.GET_NAME_VER_APP, 0, Endpoint.APP)
            name0 = rx[2:6].decode("ascii").rstrip()
            name1 = rx[6:10].decode("ascii").rstrip()
            ver = int.from_bytes(rx[10:14], byteorder="little")
            if name0 == "tk1" and name1 == "mlds" and ver == self.version:
                # Signer application already loaded
                return
            raise TKeyError(
                f"TKey is running an unknown application {name0, name1, ver}"
            )

        # If we reached here, we are in firmware mode. Load the app
        with as_file(self.app_resource) as app_path:
            self._load_app(str(app_path), secret=self.secret)

        if self._conn and self._conn.in_waiting:
            self._conn.read(self._conn.in_waiting)

    def get_pubkey(self) -> bytes:
        """Retrieve 1312-byte ML-DSA-44 public key from device in 120-byte chunks."""
        pubkey = bytearray(KEY_SIZE)
        for i in range(KEY_CHUNKS + 1):
            tx_data = bytes([i, 0, 0])  # 1 byte chunk index + 2 bytes padding
            # CMD_GET_KEY_CHUNK ID 0x11, length index 1 (4 bytes)
            rx = self.send(Cmd.GET_KEY_CHUNK, 1, Endpoint.APP, tx_data)

            if rx[2] != 0:
                raise TKeyError(f"GetPubkeyChunk NOK status: {rx[2]}")
            if rx[3] != i:
                raise TKeyError(
                    f"GetPubkeyChunk chunk index mismatch, expected {i}, got {rx[3]}"
                )

            offset = i * CHUNK_SIZE
            size = KEY_SIZE % CHUNK_SIZE if i == KEY_CHUNKS else CHUNK_SIZE
            pubkey[offset : offset + size] = rx[4 : 4 + size]
        return bytes(pubkey)

    def sign(self, formatted_msg: bytes) -> bytes:
        """Send payload to TKey and fetch 2420-byte signature."""
        # 1. Set size
        size = len(formatted_msg)
        size_bytes = size.to_bytes(4, byteorder="little")
        tx_data = bytearray(31)
        tx_data[0:4] = size_bytes
        # CMD_SET_SIZE ID 0x03, length index 2 (32 bytes)
        self.send(Cmd.SET_SIZE, 2, Endpoint.APP, bytes(tx_data))

        # 2. Load data
        offset = 0
        while offset < len(formatted_msg):
            chunk = formatted_msg[offset : offset + 127]
            # CMD_SIGN_DATA ID 0x05, length index 3 (128 bytes)
            self.send(Cmd.SIGN_DATA, 3, Endpoint.APP, chunk)
            offset += 127

        # 3. Trigger signing (blocks waiting for physical touch)
        # CMD_GET_SIG ID 0x07, length index 0 (1 byte)
        rx = self.send(Cmd.GET_SIG, 0, Endpoint.APP, timeout=60)

        if rx[2] != 0x00:
            raise TKeyError(f"Response NOK status: hex={rx.hex()}")

        # 4. Fetch signature chunks (21 chunks)
        signature = bytearray(SIG_SIZE)
        for i in range(SIG_CHUNKS + 1):
            # CMD_GET_SIG_CHUNK ID 0x13, length index 1 (4 bytes)
            rx = self.send(Cmd.GET_SIG_CHUNK, 1, Endpoint.APP, bytes([i, 0, 0]))
            if rx[2] != 0:
                raise TKeyError(f"GetSigChunk NOK status: {rx[2]}")
            if rx[3] != i:
                raise TKeyError(
                    f"GetSigChunk chunk index mismatch, expected {i}, got {rx[3]}"
                )

            offset = i * CHUNK_SIZE
            size = SIG_SIZE % CHUNK_SIZE if i == SIG_CHUNKS else CHUNK_SIZE
            signature[offset : offset + size] = rx[4 : 4 + size]

        return bytes(signature)


class TKeySigner(Signer):
    """Tillitis TKey Signer.

    Supports signing scheme "ml-dsa-44/1".
    """

    SCHEME = "tkey"

    def __init__(
        self,
        device_path: str | None,
        version: int,
        public_key: SSlibKey,
        secrets_handler: SecretsHandler | None = None,
        use_uss: bool = False,
    ) -> None:
        if public_key.scheme != "ml-dsa-44/1":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self.device_path = device_path
        self._public_key = public_key
        self.secrets_handler = secrets_handler
        self.version = version
        self.use_uss = use_uss

    @property
    def public_key(self) -> SSlibKey:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> TKeySigner:
        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"TKeySigner does not support {priv_key_uri}")

        # Extract device path (empty or "/" triggers auto-detect)
        device_path = uri.path if uri.path not in ("", "/") else None

        # Extract query parameters
        query_params = parse.parse_qs(uri.query)

        version = 4
        if "version" in query_params:
            try:
                version = int(query_params["version"][0])
            except (ValueError, IndexError):
                raise ValueError(f"Invalid version in URI: {priv_key_uri}")

        use_uss_str = query_params.get("use_uss", ["false"])[0]
        use_uss = use_uss_str.lower() == "true"

        return cls(
            device_path,
            version,
            public_key,
            secrets_handler,
            use_uss,
        )

    @classmethod
    def import_(
        cls,
        device_path: str | None = None,
        version: int = 4,
        uss: str | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from TKey device."""
        if device_path is None:
            devices = _TKey.list_devices()
            if not devices:
                raise ValueError("No TKey device found")
            device_path = devices[0]

        with _TKey(device_path, version, secret=uss) as tk:
            raw_pubkey = tk.get_pubkey()

        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))

        # Build URI with version and optional use_uss query parameters
        query = {"version": str(version)}
        if uss is not None:
            query["use_uss"] = "true"

        uri = f"{cls.SCHEME}:{device_path}?{parse.urlencode(query)}"

        return uri, key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Tillitis TKey."""
        # 1. Connect to TKey and make sure the app is loaded
        # Find device
        dev = self.device_path
        if dev is None:
            devices = _TKey.list_devices()
            if not devices:
                raise RuntimeError("No TKey device found")
            dev = devices[0]

        # Use TUF-specific message prefix
        digest = hashlib.sha512(payload).digest()
        formatted_msg = b"tuf" + bytes([1]) + digest

        secret = None
        if self.use_uss:
            if self.secrets_handler is None:
                raise ValueError("This TKey requires a secrets handler")
            secret = self.secrets_handler("User Supplied Secret")

        with _TKey(dev, self.version, secret=secret) as tk:
            sig_bytes = tk.sign(formatted_msg)

        return Signature(self.public_key.keyid, sig_bytes.hex())
