"""Signer for Tillitis TKey"""

from __future__ import annotations

import hashlib
import logging
import os
import select
from importlib.resources import as_file, files
from typing import Any, TYPE_CHECKING
from urllib import parse

try:
    # only used on linux
    import array
    import fcntl
    import termios
except ImportError:
    array = None  # type: ignore[assignment]
    fcntl = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

if TYPE_CHECKING:
    import serial


logger = logging.getLogger(__name__)

TKEYCLIENT_IMPORT_ERROR = None
try:
    from tkeyclient import error, hw, proto  # type: ignore[import-untyped]
    from tkeyclient.tkey import TKey  # type: ignore[import-untyped]
except ImportError:
    TKEYCLIENT_IMPORT_ERROR = "Signing with TKey requires the 'tkeyclient' package."

# --- Isolated TKey Custom Commands & Protocol Logic ---

if not TKEYCLIENT_IMPORT_ERROR:
    cmdGetPubkeyChunk = proto.fwCommand(0x11, 1)  # LEN_4
    rspGetPubkeyChunk = proto.fwCommand(0x12, 3)  # LEN_128
    cmdSetSize = proto.fwCommand(0x03, 2)  # LEN_32
    rspSetSize = proto.fwCommand(0x04, 1)  # LEN_4
    cmdSignData = proto.fwCommand(0x05, 3)  # LEN_128
    rspSignData = proto.fwCommand(0x06, 1)  # LEN_4
    cmdGetSig = proto.fwCommand(0x07, 0)  # LEN_1
    rspGetSig = proto.fwCommand(0x08, 3)  # LEN_128
    cmdGetSigChunk = proto.fwCommand(0x13, 1)  # LEN_4
    rspGetSigChunk = proto.fwCommand(0x14, 3)  # LEN_128
    cmdGetNameVersion = proto.fwCommand(0x09, 0)  # LEN_1
    rspGetNameVersion = proto.fwCommand(0x0A, 2)  # LEN_32


def _get_app_name_version(conn: serial.Serial) -> tuple[str, str, int]:
    """Query name and version from the running signer application (ENDPOINT_APP)."""
    id = 2
    rx:bytes = proto.send_command(conn, cmdGetNameVersion, proto.ENDPOINT_APP, id)
    name0 = rx[2:6].decode("ascii", errors="ignore").rstrip()
    name1 = rx[6:10].decode("ascii", errors="ignore").rstrip()
    version = int.from_bytes(rx[10:14], byteorder="little")
    return name0, name1, version


def _get_pubkey_from_tkey(conn: serial.Serial) -> bytes:
    """Retrieve 1312-byte ML-DSA-44 public key from device in 120-byte chunks."""
    id = 2
    pubkey = bytearray(1312)
    for i in range(11):
        tx_data = bytes([i, 0, 0])  # 1 byte chunk index + 2 bytes padding
        rx = proto.send_command(
            conn, cmdGetPubkeyChunk, proto.ENDPOINT_APP, id, tx_data
        )

        if rx[2] != 0:
            raise ValueError(f"GetPubkeyChunk NOK status: {rx[2]}")
        if rx[3] != i:
            raise ValueError(
                f"GetPubkeyChunk chunk index mismatch, expected {i}, got {rx[3]}"
            )

        size = 112 if i == 10 else 120
        offset = i * 120
        pubkey[offset : offset + size] = rx[4 : 4 + size]
    return bytes(pubkey)


def _sign_on_tkey(conn: serial.Serial, formatted_msg: bytes) -> bytes:
    """Send 68-byte message to TKey, trigger touch-signing, and fetch 2420-byte signature."""
    id = 2

    # 1. Set size
    size = len(formatted_msg)
    size_bytes = size.to_bytes(4, byteorder="little")
    tx_data = bytearray(31)
    tx_data[0:4] = size_bytes
    proto.send_command(conn, cmdSetSize, proto.ENDPOINT_APP, id, bytes(tx_data))

    # 2. Load data
    offset = 0
    while offset < len(formatted_msg):
        chunk = formatted_msg[offset : offset + 127]
        if len(chunk) < 127:
            chunk = chunk + b"\x00" * (127 - len(chunk))
        proto.send_command(conn, cmdSignData, proto.ENDPOINT_APP, id, chunk)
        offset += 127

    # 3. Trigger signing (blocks waiting for physical touch)
    old_timeout = conn.timeout
    conn.timeout = 60
    try:
        rx = proto.send_command(conn, cmdGetSig, proto.ENDPOINT_APP, id)
    finally:
        conn.timeout = old_timeout

    # Validate response format:
    # header_byte (1) + RSP_GET_SIG ID (1) + status_byte (1) + data (126) = 129
    if len(rx) < 129 or rx[1] != 0x08 or rx[2] != 0x00:
        raise error.TKeyProtocolError(
            f"Response mismatch or NOK status: len={len(rx)} hex={rx.hex()}"
        )

    # 4. Fetch signature chunks (21 chunks)
    signature = bytearray(2420)
    for i in range(21):
        rx = proto.send_command(
            conn, cmdGetSigChunk, proto.ENDPOINT_APP, id, bytes([i, 0, 0])
        )
        if rx[2] != 0:
            raise ValueError(f"GetSigChunk NOK status: {rx[2]}")
        if rx[3] != i:
            raise ValueError(
                f"GetSigChunk chunk index mismatch, expected {i}, got {rx[3]}"
            )

        chunk_offset = i * 120
        chunk_size = 20 if i == 20 else 120
        signature[chunk_offset : chunk_offset + chunk_size] = rx[4 : 4 + chunk_size]

    return bytes(signature)


class RawSerialConnection:
    """A raw Python serial connection.

    Uses standard os.open/ioctl configured in raw mode at 62500 baud.
    """

    def __init__(self, port: str) -> None:
        self.port = port
        self.baudrate = 62500
        self.timeout = 30.0  # Constant timeout covering long touch signatures
        self.fd: int | None = None
        self.open()

    def open(self) -> None:
        if self.fd is not None:
            return

        self.fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            # 1. Use standard termios to configure raw 8N1 mode
            attrs = termios.tcgetattr(self.fd)

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
                termios.CSIZE
                | termios.PARENB
                | termios.CSTOPB
                | termios.CRTSCTS
            )
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL

            # Set speed elements to standard constant to avoid EINVAL on custom speeds
            attrs[4] = termios.B9600
            attrs[5] = termios.B9600

            # Apply standard configuration
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)

            # 2. Use termios2 ioctls ONLY to set the custom 62500 baud rate
            tcgets2 = 0x802C542A
            tcsets2 = 0x402C542B
            bother = 0o010000

            buf = array.array("i", [0] * 64)
            fcntl.ioctl(self.fd, tcgets2, buf)

            buf[2] &= ~0x100F  # Clear CBAUD/CBAUDEX speed flags
            buf[2] |= bother   # Flag for custom speed (BOTHER)
            buf[9] = buf[10] = 62500  # Set custom speed

            fcntl.ioctl(self.fd, tcsets2, buf)

            # 3. Restore blocking mode
            flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            fcntl.fcntl(self.fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

            # 4. Acquire exclusive access
            tiocexcl = 0x540C
            fcntl.ioctl(self.fd, tiocexcl, 0)
        except Exception:
            os.close(self.fd)
            self.fd = None
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

    def reset_input_buffer(self) -> None: pass
    def reset_output_buffer(self) -> None: pass

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


def _connect_tkey(device_path: str) -> TKey:
    """Connect to TKey device at 62500 baud.

    Use RawSerial on linux because pyserial seemed to have an issue with the baud rate
    and multiple connections
    """
    if os.uname().sysname == "Linux":
        tk = TKey(device_path, connect=False)
        raw_conn = RawSerialConnection(device_path)
        tk.conn = raw_conn
    else:
        tk = TKey(device_path, speed=62500, connect=True)

    return tk


# --- End of Isolated TKey Logic ---


class TKeySigner(Signer):
    """Tillitis TKey Signer.

    Supports signing scheme "ml-dsa-44/1".
    """

    # TODO support "uss" as secret: see tk.load_app()

    SCHEME = "tkey"

    def __init__(
        self,
        device_path: str | None,
        public_key: SSlibKey,
        secrets_handler: SecretsHandler | None = None,
    ) -> None:
        if TKEYCLIENT_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEYCLIENT_IMPORT_ERROR)

        if public_key.scheme != "ml-dsa-44/1":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self.device_path = device_path
        self._public_key = public_key
        self.secrets_handler = secrets_handler

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
        if TKEYCLIENT_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEYCLIENT_IMPORT_ERROR)

        if not isinstance(public_key, SSlibKey):
            raise ValueError(f"expected SSlibKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)
        if uri.scheme != cls.SCHEME:
            raise ValueError(f"TKeySigner does not support {priv_key_uri}")

        # Extract device path (empty or "/" triggers auto-detect)
        device_path = uri.path if uri.path not in ("", "/") else None

        return cls(device_path, public_key, secrets_handler)

    @classmethod
    def import_(
        cls,
        device_path: str | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from TKey device."""
        if TKEYCLIENT_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEYCLIENT_IMPORT_ERROR)

        if device_path is None:
            devices = hw.list_devices()
            if not devices:
                raise ValueError("No TKey device found")
            device_path = devices[0].device

        tk = _connect_tkey(device_path)
        try:
            cls._ensure_app_loaded(tk)
            raw_pubkey = _get_pubkey_from_tkey(tk.conn)
        finally:
            tk.disconnect()

        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))

        # Build URI
        uri = f"{cls.SCHEME}:{device_path}"

        return uri, key

    @classmethod
    def _ensure_app_loaded(cls, tk: TKey) -> None:
        """Check if signer app is loaded on TKey, and load it in firmware mode."""
        # 1. Try to query firmware mode name and version
        try:
            fw = tk.get_name_version()
            if fw[0] != "tk1" or fw[1] != "mkdf":
                raise RuntimeError(f"TKey is running an unknown firmware {fw}")
        except (error.TKeyStatusError, error.TKeyReadError, error.TKeyProtocolError):
            # The running application rejected the firmware command, or timed out
            # Query application name and version
            try:
                name0, name1, _ = _get_app_name_version(tk.conn)
            except Exception as e:
                raise RuntimeError("TKey is unresponsive") from e
            if name0 == "tk1" and name1 == "mlds":
                # Signer application already loaded
                return
            raise RuntimeError("TKey is running an unknown application")

        # If we reached here, we are in firmware mode. Load the app
        app_resource = files("securesystemslib.signer").joinpath("app.bin")
        with as_file(app_resource) as app_path:
            tk.load_app(str(app_path))

        if tk.conn.in_waiting:
            tk.conn.read(tk.conn.in_waiting)

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Tillitis TKey."""
        # 1. Connect to TKey and make sure the app is loaded
        # Find device
        dev = self.device_path
        if dev is None:
            devices = hw.list_devices()
            if not devices:
                raise RuntimeError("No TKey device found")
            dev = devices[0].device

        # Use TUF-specific message prefix
        digest = hashlib.sha512(payload).digest()
        formatted_msg = b"tuf" + bytes([1]) + digest

        tk = _connect_tkey(dev)
        try:
            self._ensure_app_loaded(tk)
            sig_bytes = _sign_on_tkey(tk.conn, formatted_msg)
        finally:
            tk.disconnect()

        return Signature(self.public_key.keyid, sig_bytes.hex())
