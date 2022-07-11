from slack_sdk import WebClient


def slack(emails, csv_file_path, slack_bot_token):
    client = WebClient(token=slack_bot_token)
    print("Sending report to - ", emails)
    for email in emails:
        user_data = client.users_lookupByEmail(email=email)
        with open(csv_file_path, 'rb') as csvfile:
            client.files_upload(file=csvfile, channels=[user_data["user"]["id"]])
