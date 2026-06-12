"""Tillitis TKey ML-DSA signer implementation

This class implements a host application for a ML-DSA TKey signer.
The binary comes from https://github.com/jku/tkey-device-signer/tree/mldsa
"""

from __future__ import annotations

import logging

from securesystemslib.signer._tkey.tkey import (
    Cmd,
    LenIdx,
    Rsp,
    TKey,
    TKeyError,
)

logger = logging.getLogger(__name__)


class MldsaRsp:
    SET_SIZE = Rsp(0x04, LenIdx.I4)
    SIGN_DATA = Rsp(0x06, LenIdx.I4)
    GET_SIG = Rsp(0x08, LenIdx.I128)
    GET_KEY_CHUNK = Rsp(0x12, LenIdx.I128)
    GET_SIG_CHUNK = Rsp(0x14, LenIdx.I128)
    GET_NAME_VER_APP = Rsp(0x0A, LenIdx.I32)


class MldsaCmd:
    SET_SIZE = Cmd(0x03, 3, LenIdx.I32, (MldsaRsp.SET_SIZE,))
    SIGN_DATA = Cmd(0x05, 3, LenIdx.I128, (MldsaRsp.SIGN_DATA,))
    GET_SIG = Cmd(0x07, 3, LenIdx.I1, (MldsaRsp.GET_SIG,))
    GET_KEY_CHUNK = Cmd(0x11, 3, LenIdx.I4, (MldsaRsp.GET_KEY_CHUNK,))
    GET_SIG_CHUNK = Cmd(0x13, 3, LenIdx.I4, (MldsaRsp.GET_SIG_CHUNK,))
    GET_NAME_VER_APP = Cmd(0x09, 3, LenIdx.I1, (MldsaRsp.GET_NAME_VER_APP,))


NAME_MLDSA = ("tk1", "mlds")

# Maximum size for data to sign
MAX_SIGN_SIZE = 4096

# Protocol chunking
CHUNK_SIZE = 120
SIG_SIZE = 2420
KEY_SIZE = 1312
SIG_CHUNKS = SIG_SIZE // CHUNK_SIZE
KEY_CHUNKS = KEY_SIZE // CHUNK_SIZE


class TKeyMldsa(TKey):
    """Client for a TKey ML-DSA signer application"""

    def __init__(
        self,
        device: str | None,
        binary: bytes,
        version: int,
        secret: str | None,
    ) -> None:
        super().__init__(device)

        if not self.load_app(binary, secret):
            # TKey is not in firmware mode: Query application name and version
            rx = self.send(MldsaCmd.GET_NAME_VER_APP)
            name = (rx[2:6].decode("ascii").rstrip(), rx[6:10].decode("ascii").rstrip())
            ver = int.from_bytes(rx[10:14], byteorder="little")
            if name == NAME_MLDSA and ver == version:
                return  # Signer application is already loaded

            raise TKeyError(
                f"TKey is running an unknown application {name, ver}, "
                f"expected {NAME_MLDSA, version}"
            )

    def get_pubkey(self) -> bytes:
        """Retrieve 1312-byte ML-DSA-44 public key from device in 120-byte chunks."""
        pubkey = bytearray(KEY_SIZE)
        for i in range(KEY_CHUNKS + 1):
            rx = self.send(MldsaCmd.GET_KEY_CHUNK, bytes([i, 0, 0]))

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
        if size > MAX_SIGN_SIZE:
            raise ValueError(
                f"Message size {size} exceeds maximum allowed size {MAX_SIGN_SIZE}"
            )
        size_bytes = size.to_bytes(4, byteorder="little")
        tx_data = bytearray(31)
        tx_data[0:4] = size_bytes
        self.send(MldsaCmd.SET_SIZE, bytes(tx_data))

        # 2. Load data
        offset = 0
        while offset < len(formatted_msg):
            self.send(MldsaCmd.SIGN_DATA, formatted_msg[offset : offset + 127])
            offset += 127

        # 3. Trigger signing (blocks waiting for physical touch)
        rx = self.send(MldsaCmd.GET_SIG, timeout=60)

        if rx[2] != 0x00:
            raise TKeyError(f"Response NOK status: hex={rx.hex()}")

        # 4. Fetch signature chunks (21 chunks)
        signature = bytearray(SIG_SIZE)
        for i in range(SIG_CHUNKS + 1):
            rx = self.send(MldsaCmd.GET_SIG_CHUNK, bytes([i, 0, 0]))
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
