import base64
import os

extra_accept_header = ', '.join([
    'application/json; charset=utf-8',
    'application/vnd.xyz.feature-flag+json',
])


def encrypt(key, kms, value):
    return base64.b64encode(kms.encrypt(
        KeyId=key,
        Plaintext=bytearray(value, 'utf-8'),
        EncryptionContext={
            'LambdaFunctionName': 'test-function-name'
        }
    )['CiphertextBlob']).decode('utf-8')


def set_up(kms):
    kms_key = kms.create_key(
        Policy='string',
        Description='string',
    )['KeyMetadata']['KeyId']
    os.environ["AUTH_URL"] = 'http://authserver.com'
    os.environ["CONSIGNMENT_API_URL"] = "http://testserver.com"
    os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "test-function-name"
    os.environ["CLIENT_ID"] = "tdr-reporting"
    os.environ['CLIENT_SECRET'] = encrypt(kms_key, kms, "client-secret")


def access_token():
    return {'access_token': 'ABCD'}
