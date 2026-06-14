"""Tillitis TKey signer implementation

This class implements a host application for a TKey signer. The design supports
a specific application protocol (see SignCmd) but allows for different device
applications for different signing algorithms. ML-DSA and ed25519 signers are
currently defined.

The binary comes from https://github.com/jku/tkey-device-signer/tree/mldsa
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from securesystemslib.signer._tkey.tkey import Cmd, LenIdx, Rsp, TKey, TKeyError

logger = logging.getLogger(__name__)

MAX_SIGN_SIZE = 4096
CHUNK_SIZE = 120


@dataclass
class SignApp:
    """Signapp represents the *device* signing application"""

    name: tuple[str, str]
    sig_size: int
    key_size: int
    binary: bytes
    version: int

    @classmethod
    def mldsa(cls, binary: bytes, version: int) -> SignApp:
        return cls(("tk1", "mlds"), 2420, 1312, binary, version)

    @classmethod
    def ed25519(cls, binary: bytes, version: int) -> SignApp:
        return cls(("tk1", "sign"), 64, 32, binary, version)


class SignRsp:
    """Application responses"""

    SET_SIZE = Rsp(0x04, LenIdx.I4)
    SIGN_DATA = Rsp(0x06, LenIdx.I4)
    GET_SIG = Rsp(0x08, LenIdx.I128)
    GET_KEY_CHUNK = Rsp(0x12, LenIdx.I128)
    GET_SIG_CHUNK = Rsp(0x14, LenIdx.I128)
    GET_NAME_VER_APP = Rsp(0x0A, LenIdx.I32)


class SignCmd:
    """Application commands"""

    SET_SIZE = Cmd(0x03, 3, LenIdx.I32, (SignRsp.SET_SIZE,))
    SIGN_DATA = Cmd(0x05, 3, LenIdx.I128, (SignRsp.SIGN_DATA,))
    GET_SIG = Cmd(0x07, 3, LenIdx.I1, (SignRsp.GET_SIG,))
    GET_KEY_CHUNK = Cmd(0x11, 3, LenIdx.I4, (SignRsp.GET_KEY_CHUNK,))
    GET_SIG_CHUNK = Cmd(0x13, 3, LenIdx.I4, (SignRsp.GET_SIG_CHUNK,))
    GET_NAME_VER_APP = Cmd(0x09, 3, LenIdx.I1, (SignRsp.GET_NAME_VER_APP,))


class TKeySign(TKey):
    """Client for a TKey signer application"""

    def __init__(
        self,
        app: SignApp,
        device: str | None = None,
        secret: str | None = None,
    ) -> None:
        super().__init__(device)
        self.key_size = app.key_size
        self.key_chunks = self.key_size // CHUNK_SIZE
        self.sig_size = app.sig_size
        self.sig_chunks = self.sig_size // CHUNK_SIZE

        if not self.load_app(app.binary, secret):
            # TKey is not in firmware mode: Query application name and version
            rx = self.send(SignCmd.GET_NAME_VER_APP)
            name = (rx[2:6].decode("ascii").rstrip(), rx[6:10].decode("ascii").rstrip())
            ver = int.from_bytes(rx[10:14], byteorder="little")
            if name == app.name and ver == app.version:
                return  # Signer application is already loaded

            raise TKeyError(
                f"TKey is running an unknown application {name, ver}, "
                f"expected {app.name, app.version}"
            )

    def get_pubkey(self) -> bytes:
        """Retrieve public key bytes from device in chunks."""
        pubkey = bytearray(self.key_size)
        for i in range(self.key_chunks + 1):
            rx = self.send(SignCmd.GET_KEY_CHUNK, bytes([i, 0, 0]))

            if rx[2] != 0:
                raise TKeyError(f"GetPubkeyChunk NOK status: {rx[2]}")
            if rx[3] != i:
                raise TKeyError(
                    f"GetPubkeyChunk chunk index mismatch, expected {i}, got {rx[3]}"
                )

            offset = i * CHUNK_SIZE
            size = self.key_size % CHUNK_SIZE if i == self.key_chunks else CHUNK_SIZE
            pubkey[offset : offset + size] = rx[4 : 4 + size]
        return bytes(pubkey)

    def sign(self, formatted_msg: bytes) -> bytes:
        """Send payload to TKey and fetch signature bytes in chunks."""
        # 1. Set size
        size = len(formatted_msg)
        if size > MAX_SIGN_SIZE:
            raise ValueError(
                f"Message size {size} exceeds maximum allowed size {MAX_SIGN_SIZE}"
            )
        size_bytes = size.to_bytes(4, byteorder="little")
        tx_data = bytearray(31)
        tx_data[0:4] = size_bytes
        self.send(SignCmd.SET_SIZE, bytes(tx_data))

        # 2. Load data
        offset = 0
        while offset < len(formatted_msg):
            self.send(SignCmd.SIGN_DATA, formatted_msg[offset : offset + 127])
            offset += 127

        # 3. Trigger signing (blocks waiting for physical touch)
        rx = self.send(SignCmd.GET_SIG, timeout=60)

        if rx[2] != 0x00:
            raise TKeyError(f"Response NOK status: hex={rx.hex()}")

        # 4. Fetch signature chunks
        signature = bytearray(self.sig_size)
        for i in range(self.sig_chunks + 1):
            rx = self.send(SignCmd.GET_SIG_CHUNK, bytes([i, 0, 0]))
            if rx[2] != 0:
                raise TKeyError(f"GetSigChunk NOK status: {rx[2]}")
            if rx[3] != i:
                raise TKeyError(
                    f"GetSigChunk chunk index mismatch, expected {i}, got {rx[3]}"
                )

            offset = i * CHUNK_SIZE
            size = self.sig_size % CHUNK_SIZE if i == self.sig_chunks else CHUNK_SIZE
            signature[offset : offset + size] = rx[4 : 4 + size]

        return bytes(signature)
