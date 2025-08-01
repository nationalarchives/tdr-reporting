import os
import boto3
from slack_sdk import WebClient
from datetime import datetime
from base64 import b64decode


def slack(event, environment, csv_file_path):
    # Only proceed if userName provided and non-empty
    user_names = event.get("userName") or []
    if not user_names:
        return
    # Initialize Slack client with raw token
    token = decode("SLACK_BOT_TOKEN")
    client = WebClient(token=token, timeout=180)
    channel_id = decode("TDR_REPORTING_SLACK_CHANNEL_ID")
    report_type = event.get("reportType", "standard")
    title = f"TDR {report_type} report"
    initial_comment = f"{report_type.title()} report requested by {user_names} on {datetime.today().strftime('%d-%m-%Y @ %H:%M')} [{environment}]"
    resp = client.files_upload(
        channels=channel_id,
        file=csv_file_path,
        title=title,
        initial_comment=initial_comment
    )
    if not resp.get("ok"):
        raise SlackApiError(f"Error uploading file: {resp.get('error')}", resp)

def decode(env_var_name):
    client = boto3.client("kms")
    decoded = client.decrypt(CiphertextBlob=b64decode(os.environ[env_var_name]),
                             EncryptionContext={"LambdaFunctionName": os.environ["AWS_LAMBDA_FUNCTION_NAME"]})
    return decoded["Plaintext"].decode("utf-8")
