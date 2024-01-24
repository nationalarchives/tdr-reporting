import os
import boto3
from slack_sdk import WebClient
from datetime import datetime
from base64 import b64decode


def slack(event, environment, csv_file_path):
    client = WebClient(token=decode("SLACK_BOT_TOKEN"), timeout=180)
    user_name = event["userName"]
    report_type = event["reportType"]

    client.files_upload_v2(
        file=csv_file_path,
        title=f"TDR {report_type} report",
        channel=decode("TDR_REPORTING_SLACK_CHANNEL_ID"),
        initial_comment=f"{report_type.title()} report requested by {user_name} on {datetime.today().strftime('%d-%m-%Y @ %H:%M')} [{environment}]",
    )

def decode(env_var_name):
    client = boto3.client("kms")
    decoded = client.decrypt(CiphertextBlob=b64decode(os.environ[env_var_name]),
                             EncryptionContext={"LambdaFunctionName": os.environ["AWS_LAMBDA_FUNCTION_NAME"]})
    return decoded["Plaintext"].decode("utf-8")
