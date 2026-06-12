"""Tillitis TKey Signer base

This class is used to build host/client applications for a TKey signer.
It implements the Firmware protocol and provides serial IO as well
as some helpers for the actual application implementation.

Links:
* Framing protocol https://dev.tillitis.se/protocol/#framing-protocol
"""

from __future__ import annotations

import hashlib
import logging
import os
import select
import sys
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Protocol, TypeVar

# Linux-specific stdlib modules: See _RawSerialConnection
if sys.platform == "linux":
    import array
    import fcntl
    import termios

import serial  # type: ignore[import-untyped]
from serial.tools import list_ports  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# USB Vendor & Product ID for TKey
TKEY_USB_VID = 0x1207
TKEY_USB_PID = 0x8887

# Maximum size for applications to load onto TKey (100 KiB)
APP_MAXSIZE = 100 * 1024

ENDPOINT_FW = 2


class FwCmd:
    NAME_VERSION = 0x01
    LOAD_APP = 0x03
    LOAD_APP_DATA = 0x05


class FwRsp:
    NAME_VERSION = 0x02
    LOAD_APP = 0x04
    LOAD_APP_DATA = 0x06
    LOAD_APP_DATA_READY = 0x07


# Data lengths corresponding to header length bits (0, 1, 2, 3)
PROTO_DATA_LENGTH = [1, 4, 32, 128]


# Length indices mapping to PROTO_DATA_LENGTH
class LenIdx:
    I1 = 0
    I4 = 1
    I32 = 2
    I128 = 3


_TKey = TypeVar("_TKey", bound="TKey")


class TKeyError(Exception):
    """Base class for TKey errors."""


class TKeyAppError(TKeyError):
    """Raised when loading the signer application fails."""


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


class _RawSerialConnection:
    """A raw Python serial connection.

    This helper exists because pyserial just did not work with TKey
    on linux
    """

    def __init__(self, port: str, baudrate: int, timeout: float) -> None:
        self.timeout = timeout
        self._fd: int | None = self._open(port, baudrate)

    def _open(self, port: str, baudrate: int) -> int:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
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
            buf[9] = buf[10] = baudrate  # Set custom speed

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
        if self._fd is None:
            raise ValueError("Port is closed")
        return os.write(self._fd, data)

    def read(self, n: int) -> bytes:
        """Read exactly n bytes blockingly, respecting the configured timeout."""
        if self._fd is None:
            raise ValueError("Port is closed")
        data = bytearray()
        while len(data) < n:
            r, _, _ = select.select([self._fd], [], [], self.timeout)
            if not r:
                break  # Timeout
            chunk = os.read(self._fd, n - len(data))
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
        if self._fd is None:
            return 0
        buf = array.array("i", [0])
        try:
            fcntl.ioctl(self._fd, termios.FIONREAD, buf)
            return buf[0]
        except Exception:
            return 0

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


class TKey(ABC):
    """Base TKey Client

    TKey handles serial IO, provides load_app() for loading an application.

    """

    def __init__(
        self,
        device: str | None,
    ) -> None:

        self._conn: _SerialConnection | None = None
        self._fid = 0

        self._connect(device, baudrate=62500, timeout=5.0)

    @staticmethod
    def _find_device(device_path: str | None) -> str:
        """Discover TKey device serial port using pyserial."""

        ports = list_ports.comports()
        devices = sorted(
            p.device for p in ports if p.vid == TKEY_USB_VID and p.pid == TKEY_USB_PID
        )

        if device_path is None:
            if not devices:
                raise TKeyError("No TKey devices found")
            device_path = devices[0]
        elif device_path not in devices:
            raise TKeyError(f"TKey device {device_path} not found")
        return device_path

    def _connect(self, device: str | None, baudrate: int, timeout: float) -> None:
        port = self._find_device(device)

        if sys.platform == "linux":
            self._conn = _RawSerialConnection(port, baudrate, timeout)
        else:
            try:
                self._conn = serial.Serial(port, baudrate=baudrate, timeout=timeout)
            except Exception as e:
                raise TKeyError(f"Failed to open serial port {port}: {e}") from e

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception as e:
                logger.debug("Failed to close TKey connection: %s", e)
            self._conn = None

    def __enter__(self: _TKey) -> _TKey:
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
            raise TKeyProtocolError("Response status code not OK (1)")

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

        self.validate_response(resp_eid, cmd_id, resp_data[0], resp_len_idx)

        response = bytearray(1 + resp_len)
        response[0] = header_val
        response[1:] = resp_data
        return bytes(response)

    @abstractmethod
    def validate_response(
        self, eid: int, cmd_id: int, resp_id: int, resp_len_idx: int
    ) -> None: ...

    def validate_firmware_response(
        self, cmd_id: int, resp_id: int, resp_len_idx: int
    ) -> None:
        """Validate firmware response ID and length index matches expected response."""
        match (cmd_id, resp_id, resp_len_idx):
            case (FwCmd.NAME_VERSION, FwRsp.NAME_VERSION, LenIdx.I32):
                pass
            case (FwCmd.LOAD_APP, FwRsp.LOAD_APP, LenIdx.I4):
                pass
            case (FwCmd.LOAD_APP_DATA, FwRsp.LOAD_APP_DATA, LenIdx.I4):
                pass
            case (FwCmd.LOAD_APP_DATA, FwRsp.LOAD_APP_DATA_READY, LenIdx.I128):
                pass
            case (_, _, _):
                raise TKeyProtocolError(
                    f"Unexpected firmware protocol response: cmd={cmd_id:#x},"
                    f" response={resp_id:#x}, len_index={resp_len_idx}"
                )

    def load_app(self, app_binary: bytes, secret: str | None = None) -> bool:
        """
        Returns True if the application as loaded, False if the device is not
        in Firmware mode
        """
        file_size = len(app_binary)
        if file_size > APP_MAXSIZE:
            raise TKeyAppError(
                f"Application binary is too large ({file_size} > {APP_MAXSIZE})"
            )

        try:
            # Query firmware name
            rx = self.send(FwCmd.NAME_VERSION, 0, ENDPOINT_FW)
        except TKeyError:
            # Not in firmware mode
            # TODO would be nice to only do this on NOK response, not other errors
            return False

        # we are in firmware mode. Load the app
        fw_name0 = rx[2:6].decode("ascii").rstrip()
        fw_name1 = rx[6:10].decode("ascii").rstrip()
        if fw_name0 != "tk1" or fw_name1 != "mkdf":
            raise TKeyError(f"TKey is running an unknown firmware {fw_name0, fw_name1}")

        file_digest = hashlib.blake2s(app_binary, digest_size=32).digest()

        # cmdLoadApp ID 0x03, length index 3 (128 bytes)
        data = bytearray(127)
        data[0:4] = file_size.to_bytes(4, byteorder="little")
        if secret is not None:
            data[4] = 1
            uss = hashlib.blake2s(secret.encode("utf-8"), digest_size=32)
            data[5 : 5 + 32] = uss.digest()

        response = self.send(FwCmd.LOAD_APP, 3, ENDPOINT_FW, bytes(data))
        if response[2] == 1:
            raise TKeyAppError("Device not ready (STATUS_BAD)")

        result_digest = self._load_app_data(app_binary)
        if file_digest != result_digest:
            raise TKeyAppError(
                "App digest does not match "
                f"({file_digest.hex()} != {result_digest.hex()})"
            )

        if self._conn and self._conn.in_waiting:
            self._conn.read(self._conn.in_waiting)

        return True

    def _load_app_data(self, file_data: bytes) -> bytes:
        # cmdLoadAppData ID 0x05, length index 3 (128 bytes)
        digest = b""
        offset = 0
        while offset < len(file_data):
            chunk = file_data[offset : offset + 127]
            response = self.send(FwCmd.LOAD_APP_DATA, 3, ENDPOINT_FW, chunk)
            response_id = response[1]
            status = response[2]
            if status == 1:
                raise TKeyError("Bad status when writing app data")

            if response_id == FwRsp.LOAD_APP_DATA_READY:
                digest = response[3:35]
            elif response_id != FwRsp.LOAD_APP_DATA:
                raise TKeyProtocolError(f"Unexpected response code {response_id}")

            offset += 127

        return digest
