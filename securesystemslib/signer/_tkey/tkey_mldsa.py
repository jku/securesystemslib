"""Tillitis TKey ML-DSA signer implementation

This class implements a host application for a ML-DSA TKey signer.
The binary comes from https://github.com/jku/tkey-device-signer/tree/mldsa
"""

from __future__ import annotations

import logging

from securesystemslib.signer._tkey.tkey import (
    ENDPOINT_FW,
    LenIdx,
    TKey,
    TKeyError,
    TKeyProtocolError,
)

logger = logging.getLogger(__name__)

ENDPOINT_MLDSA = 3
NAME_MLDSA = ("tk1", "mlds")


class MldsaCmd:
    SET_SIZE = 0x03
    SIGN_DATA = 0x05
    GET_SIG = 0x07
    GET_KEY_CHUNK = 0x11
    GET_SIG_CHUNK = 0x13
    GET_NAME_VER_APP = 0x09


class MldsaRsp:
    SET_SIZE = 0x04
    SIGN_DATA = 0x06
    GET_SIG = 0x08
    GET_KEY_CHUNK = 0x12
    GET_SIG_CHUNK = 0x14
    GET_NAME_VER_APP = 0x0A


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
            rx = self.send(MldsaCmd.GET_NAME_VER_APP, 0, ENDPOINT_MLDSA)
            name = (rx[2:6].decode("ascii").rstrip(), rx[6:10].decode("ascii").rstrip())
            ver = int.from_bytes(rx[10:14], byteorder="little")
            if name == NAME_MLDSA and ver == version:
                return  # Signer application is already loaded

            raise TKeyError(
                f"TKey is running an unknown application {name, ver}, "
                f"expected {NAME_MLDSA, version}"
            )

    def validate_response(
        self, eid: int, cmd_id: int, resp_id: int, resp_len_idx: int
    ) -> None:
        """Validate response ID and length index matches expected response."""

        if eid == ENDPOINT_FW:
            self.validate_firmware_response(cmd_id, resp_id, resp_len_idx)
        elif eid == ENDPOINT_MLDSA:
            self.validate_app_response(cmd_id, resp_id, resp_len_idx)
        else:
            raise TKeyProtocolError(f"Unexpected endpoint={eid:#x}")

    def validate_app_response(
        self, cmd_id: int, resp_id: int, resp_len_idx: int
    ) -> None:
        match (cmd_id, resp_id, resp_len_idx):
            case (MldsaCmd.GET_KEY_CHUNK, MldsaRsp.GET_KEY_CHUNK, LenIdx.I128):
                pass
            case (MldsaCmd.SET_SIZE, MldsaRsp.SET_SIZE, LenIdx.I4):
                pass
            case (MldsaCmd.SIGN_DATA, MldsaRsp.SIGN_DATA, LenIdx.I4):
                pass
            case (MldsaCmd.GET_SIG, MldsaRsp.GET_SIG, LenIdx.I128):
                pass
            case (MldsaCmd.GET_SIG_CHUNK, MldsaRsp.GET_SIG_CHUNK, LenIdx.I128):
                pass
            case (MldsaCmd.GET_NAME_VER_APP, MldsaRsp.GET_NAME_VER_APP, LenIdx.I32):
                pass
            case (_, _, _):
                raise TKeyProtocolError(
                    f"Unexpected application protocol response: cmd={cmd_id:#x},"
                    f" response={resp_id:#x}, len_index={resp_len_idx}"
                )

    def get_pubkey(self) -> bytes:
        """Retrieve 1312-byte ML-DSA-44 public key from device in 120-byte chunks."""
        pubkey = bytearray(KEY_SIZE)
        for i in range(KEY_CHUNKS + 1):
            tx_data = bytes([i, 0, 0])  # 1 byte chunk index + 2 bytes padding
            # CMD_GET_KEY_CHUNK ID 0x11, length index 1 (4 bytes)
            rx = self.send(MldsaCmd.GET_KEY_CHUNK, 1, ENDPOINT_MLDSA, tx_data)

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
        # CMD_SET_SIZE ID 0x03, length index 2 (32 bytes)
        self.send(MldsaCmd.SET_SIZE, 2, ENDPOINT_MLDSA, bytes(tx_data))

        # 2. Load data
        offset = 0
        while offset < len(formatted_msg):
            chunk = formatted_msg[offset : offset + 127]
            # CMD_SIGN_DATA ID 0x05, length index 3 (128 bytes)
            self.send(MldsaCmd.SIGN_DATA, 3, ENDPOINT_MLDSA, chunk)
            offset += 127

        # 3. Trigger signing (blocks waiting for physical touch)
        # CMD_GET_SIG ID 0x07, length index 0 (1 byte)
        rx = self.send(MldsaCmd.GET_SIG, 0, ENDPOINT_MLDSA, timeout=60)

        if rx[2] != 0x00:
            raise TKeyError(f"Response NOK status: hex={rx.hex()}")

        # 4. Fetch signature chunks (21 chunks)
        signature = bytearray(SIG_SIZE)
        for i in range(SIG_CHUNKS + 1):
            # CMD_GET_SIG_CHUNK ID 0x13, length index 1 (4 bytes)
            rx = self.send(MldsaCmd.GET_SIG_CHUNK, 1, ENDPOINT_MLDSA, bytes([i, 0, 0]))
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
