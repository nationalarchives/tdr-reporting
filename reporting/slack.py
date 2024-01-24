import os
from slack_sdk import WebClient
from datetime import datetime
from reporting import report


def slack(event, environment, csv_file_path):
    client = WebClient(token=report.decode("SLACK_BOT_TOKEN"), timeout=180)
    user_name = event["userName"]
    report_type = event["reportType"]

    client.files_upload_v2(
        file=csv_file_path,
        title=f"TDR {report_type} report",
        channel=report.decode("TDR_REPORTING_SLACK_CHANNEL_ID"),
        initial_comment=f"{report_type.title()} report requested by {user_name} on {datetime.today().strftime('%d-%m-%Y @ %H:%M')} [{environment}]",
    )
