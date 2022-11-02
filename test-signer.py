from securesystemslib import keys
from securesystemslib.signer import GCPSigner

data = "data".encode("utf-8")

pubkey = {
    "keyid": "abcd",
    "keytype": "ecdsa",
    "scheme": "ecdsa-sha2-nistp256",
    "keyval": {
        "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDJchWswdXOBpMqXkekAzwuWjL+Hx\ncw2ZonDbixh/wTf1FkpxmT8Aq6/WN6NNXOW4Rw9Lua2aKLZo2ZeNrk2VLA==\n-----END PUBLIC KEY-----\n"
    },
}


gcp_id = "projects/openssf/locations/global/keyRings/securesystemslib-test-keyring/cryptoKeys/securesystemslib-test-key/cryptoKeyVersions/1"
# This should be parsed from pubkey
hash_algo = "sha256"

signer = GCPSigner(gcp_id, hash_algo, pubkey["keyid"])
sig = signer.sign(data)

if not keys.verify_signature(pubkey, sig.to_dict(), data):
    raise RuntimeError(
        f"Failed to verify signature by {pubkey['keyid']}: sig was {sig.to_dict()}"
    )
print("OK")
