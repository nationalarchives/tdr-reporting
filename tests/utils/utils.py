import base64
import json
import os
import httpretty


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
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'
    os.environ['SLACK_BOT_TOKEN'] = encrypt(kms_key, kms, "slack_token")


def access_token():
    return {'access_token': 'ABCD'}


def setup_slack_api(response):
    httpretty.register_uri(
        httpretty.POST,
        'https://www.slack.com/api/users.lookupByEmail',
        adding_headers={},
        body=json.dumps(response),
        status=200
    )
    httpretty.register_uri(
        httpretty.POST,
        'https://www.slack.com/api/files.upload',
        adding_headers={},
        body=json.dumps({'ok': 'true'}),
        status=200
    )
