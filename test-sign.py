import argparse
import base64
import hashlib

from google.cloud import kms


def test_sign_asymmetric(project_id, location_id, keyring_id, key_id, version_id):
    """
    Sign a message using GCP KMS
    This is just a test: unrelated to SSLIB at the moment

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        version_id (string)
    """


    client = kms.KeyManagementServiceClient()
    key = client.crypto_key_version_path(project_id, location_id, keyring_id, key_id, version_id)
    print("KEY", key)

    message_bytes = "data".encode('utf-8')
    digest = {'sha256': hashlib.sha256(message_bytes).digest()}

    sign_response = client.asymmetric_sign(
        request={'name': key, 'digest': digest})

    print('Signature: {}'.format(base64.b64encode(sign_response.signature)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('project_id', help='id of the GCP project')
    parser.add_argument('location_id', help='id of the KMS location')
    parser.add_argument('keyring_id', help='id of the keyring')
    parser.add_argument('key_id', help='id of the key')
    parser.add_argument('version_id', help='id of the version')

    args = parser.parse_args()

    test_sign_asymmetric(args.project_id, args.location_id, args.keyring_id, args.key_id, args.version_id)
