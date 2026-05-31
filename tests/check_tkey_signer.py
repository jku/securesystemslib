import unittest

from securesystemslib.signer import Signer, SSlibKey, TKeySigner


class TestTKeySigner(unittest.TestCase):
    def test_tkey_signer_import_and_sign(self) -> None:
        """This test requires a physical Tillitis TKey to be available"""

        uri, pub_key = TKeySigner.import_()

        self.assertEqual(pub_key.keytype, "ml-dsa")
        self.assertEqual(pub_key.scheme, "ml-dsa-44/1")
        self.assertTrue(uri.startswith("tkey:"))

        # Get a signer from standard Signer factory, sign
        signer = Signer.from_priv_key_uri(uri, pub_key)
        signature = signer.sign(b"PQC!")

        pub_key.verify_signature(signature, b"PQC!")


if __name__ == "__main__":
    unittest.main()
