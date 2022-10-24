#!/usr/bin/env python

"""
This test confirms that signing using Google Cloud KMS works.

Requirements to successfully run it:
* Google Cloud authentication details have to be available in the
  environment (see https://github.com/googleapis/python-kms)
* The key defined in the test has to be available to the authenticated
  user

Likely the only place where both can be true is the Securesystemslib
GitHub Action environment.

NOTE: the filename is purposefully check_ rather than test_ so that test
discovery doesn't find this unittest and the tests within are only run
when explicitly invoked.
"""

import unittest

from securesystemslib import keys
from securesystemslib.signer import GCPSigner


class TestKMSKeys(unittest.TestCase):
    """Test that KMS keys can be used to sign."""

    def test_gcp(self):
        """Test that GCP KMS key works for signing

        In case of problems with KMS account, please file an issue and
        assign @jku
        """

        data = "data".encode("utf-8")

        pubkey = {
            "keyid": "abcd",
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyval": {
                "public": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/ptvrXYuUc2ZaKssHhtg/IKNbO1X\ncDWlbKqLNpaK62MKdOwDz1qlp5AGHZkTY9tO09iq1F16SvVot1BQ9FJ2dw==\n-----END PUBLIC KEY-----\n"
            },
        }

        gcp_id = "projects/python-tuf-kms/locations/global/keyRings/securesystemslib-tests/cryptoKeys/ecdsa-sha2-nistp256/cryptoKeyVersions/1"
        hash_algo = "sha256"

        signer = GCPSigner(gcp_id, hash_algo, pubkey["keyid"])
        sig = signer.sign(data)

        self.assertTrue(keys.verify_signature(pubkey, sig.to_dict(), data))


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
