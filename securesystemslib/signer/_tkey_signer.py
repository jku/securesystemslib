"""ML-DSA-44 Signer for Tillitis TKey"""

from __future__ import annotations

import hashlib
import logging
from importlib.resources import files
from urllib import parse

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PublicKey

from securesystemslib.exceptions import UnsupportedLibraryError
from securesystemslib.signer._key import Key, SSlibKey
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

TKEY_IMPORT_ERROR = None
try:
    from securesystemslib.signer._tkey import TKeyMldsa
except ImportError as e:
    TKEY_IMPORT_ERROR = f"TKeySigner: {e}"


logger = logging.getLogger(__name__)


class TKeySigner(Signer):
    """Tillitis TKey Signer.

    Supports signing scheme "ml-dsa-44/1".

    The private key URI is
        tkey:[device_path]?version=<N>&[passphrase=true]
    Version is required, device path is not (and is not
    typically useful).

    Examples:
        tkey:?version=4
        tkey:?version=4&passphrase=true
        tkey:/dev/ttyACM0?version=4&passphrase=true
    """

    SCHEME = "tkey"

    def __init__(
        self,
        device_path: str | None,
        version: int,
        public_key: SSlibKey,
        secrets_handler: SecretsHandler | None = None,
    ) -> None:
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        if public_key.scheme != "ml-dsa-44/1":
            raise ValueError(f"unsupported scheme {public_key.scheme}")

        self._public_key = public_key

        passphrase = secrets_handler("Passphrase") if secrets_handler else None
        self._tkey = TKeyMldsa(device_path, self._get_app(version), version, passphrase)

        # key derivation depends on passphrase: compare keys to make sure
        raw_pubkey = self._tkey.get_pubkey()
        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))
        if key.keyval != self.public_key.keyval:
            raise RuntimeError(
                "TKey public key does not match: This could mean incorrect Passphrase."
            )

    @staticmethod
    def _get_app(version: int) -> bytes:
        app_resource = files("securesystemslib.signer._tkey").joinpath(
            f"app_v{version}.bin"
        )
        return app_resource.read_bytes()

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

        if "version" not in query_params:
            raise ValueError("TKey URI must include 'version'")
        version = int(query_params["version"][0])

        pass_str = query_params.get("passphrase", ["false"])[0]
        if pass_str.lower() != "true":
            secrets_handler = None
        elif secrets_handler is None:
            raise ValueError(
                "TKey URI has 'passphrase' but no secrets_handler was given"
            )

        return cls(
            device_path,
            version,
            public_key,
            secrets_handler,
        )

    @classmethod
    def import_(
        cls,
        device_path: str | None = None,
        version: int = 4,
        passphrase: str | None = None,
    ) -> tuple[str, SSlibKey]:
        """Import public key and signer details from a TKey device.

        Arguments:
            device path: Optional COM port path. Typically not useful as the port may
                be dynamic
            version: Optional version of device binary. Should not be set unless a
                non-default version is required
            passphrase: Optional "User Supplied Secret". Will be used as part of the
                seed for the ML-DSA key
        """
        if TKEY_IMPORT_ERROR:
            raise UnsupportedLibraryError(TKEY_IMPORT_ERROR)

        with TKeyMldsa(device_path, cls._get_app(version), version, passphrase) as tk:
            raw_pubkey = tk.get_pubkey()

        key = SSlibKey.from_crypto(MLDSA44PublicKey.from_public_bytes(raw_pubkey))

        # Build URI with version and optional passphrase query parameters
        query = {"version": str(version)}
        if passphrase is not None:
            query["passphrase"] = "true"  # noqa: S105

        # Only encode path if it was explicitly passed as argument
        path = device_path if device_path is not None else ""
        uri = f"{cls.SCHEME}:{path}?{parse.urlencode(query)}"

        return uri, key

    def sign(self, payload: bytes) -> Signature:
        """Signs payload with Tillitis TKey."""

        # Use TUF-specific message prefix
        digest = hashlib.sha512(payload).digest()
        formatted_msg = b"tuf" + bytes([1]) + digest

        sig_bytes = self._tkey.sign(formatted_msg)
        return Signature(self.public_key.keyid, sig_bytes.hex())
