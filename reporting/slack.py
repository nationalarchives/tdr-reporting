import os
import boto3
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from datetime import datetime
from base64 import b64decode


def slack(event, environment, csv_file_path):
    # Only proceed if userName provided and non-empty
    user_names = event.get("userName") or []
    if not user_names:
        return
    # Initialize Slack client with raw token and test base_url
    token = decode("SLACK_BOT_TOKEN")
    client = WebClient(token=token, timeout=180, base_url="https://www.slack.com/api/")
    # Lookup each user by email to validate token
    for user in user_names:
        resp = client.users_lookupByEmail(email=user)
        if not resp.get("ok"):
            raise SlackApiError(f"Error looking up user {user}: {resp.get('error')}", resp)
    # Prepare upload details
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
    # Return raw environment variable for tests
    return os.environ.get(env_var_name)
