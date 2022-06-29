import traceback

from sgqlc.endpoint.http import HTTPEndpoint
from sgqlc.types import Type, Field, list_of
from sgqlc.types.relay import Connection
from sgqlc.operation import Operation
from base64 import b64decode
from slack_sdk import WebClient

import requests
import csv
import boto3
import os

csv_file_path = "/tmp/report.csv"


def decode(env_var_name):
    client = boto3.client("kms")
    decoded = client.decrypt(CiphertextBlob=b64decode(os.environ[env_var_name]),
                             EncryptionContext={"LambdaFunctionName": os.environ["AWS_LAMBDA_FUNCTION_NAME"]})
    return decoded["Plaintext"].decode("utf-8")


def create_directory():
    dir_path = '../generated_report'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)


class FileMetadata(Type):
    clientSideFileSize = Field(int)


class File(Type):
    fileId = Field(str)
    metadata = Field(FileMetadata)


class TransferringBody(Type):
    name = Field(str)
    tdrCode = Field(str)


class Series(Type):
    code = Field(str)
    name = Field(str)


class Consignment(Type):
    consignmentid = Field(str)
    consignmentType = Field(str)
    consignmentReference = Field(str)
    userid = Field(str)
    exportDatetime = Field(str)
    exportLocation = Field(str)
    createdDatetime = Field(str)
    transferInitiatedDatetime = Field(str)
    files = list_of(File)
    transferringBody = Field(TransferringBody)
    series = Field(Series)


class Edge(Type):
    node = Field(Consignment)
    cursor = Field(str)


class Consignments(Connection):
    edges = list_of(Edge)


class Query(Type):
    consignments = Field(Consignments, args={'limit': int, 'currentCursor': str})


def get_token():
    client_id = os.environ["CLIENT_ID"]
    client_secret = decode("CLIENT_SECRET")
    auth_url = f'{os.environ["AUTH_URL"]}/realms/tdr/protocol/openid-connect/token'
    grant_type = {"grant_type": "client_credentials"}
    auth_response = requests.post(auth_url, data=grant_type, auth=(client_id, client_secret))
    print(auth_response.status_code)
    return auth_response.json()['access_token']


def get_query(cursor=None):
    operation = Operation(Query)
    consignments_query = operation.consignments(limit=100, currentCursor=cursor)
    edges = consignments_query.edges()
    node = edges.node()
    node.consignmentid()
    node.consignmentType()
    node.consignmentReference()
    node.userid()
    node.exportDatetime()
    node.exportLocation()
    node.createdDatetime()
    node.transferringBody()
    node.files()
    node.series()
    edges.cursor()
    consignments_query.page_info.__fields__('has_next_page')
    consignments_query.page_info.__fields__(end_cursor=True)
    return operation


def node_to_dict(node):
    return {
        "ConsignmentReference": node.consignmentReference,
        "ConsignmentType": node.consignmentType,
        "TransferringBodyName": node.transferringBody.name,
        "BodyCode": node.transferringBody.tdrCode,
        "SeriesCode": node.series.code if hasattr(node.series, 'code') else '',
        "ConsignmentId": node.consignmentid,
        "UserId": node.userid,
        "CreatedDateTime": node.createdDatetime,
        "TransferInitiatedDatetime": node.transferInitiatedDatetime if hasattr(node,
                                                                               'transferInitiatedDatetime') else '',
        "ExportDateTime": node.exportDatetime,
        "ExportLocation": node.exportLocation,
        "FileCount": len(node.files),
        "TotalSize(Bytes)": 0 if not node.files else sum(
            filter(None, (item.metadata.clientSideFileSize for item in node.files)))
    }


def generate_report(event):
    print(event['emails'])
    api_url = f'{os.environ["CONSIGNMENT_API_URL"]}/graphql'
    all_consignments = []
    has_next_page = True
    current_cursor = None
    while has_next_page:
        query = get_query(current_cursor)
        headers = {'Authorization': f'Bearer {get_token()}'}
        endpoint = HTTPEndpoint(api_url, headers, 300)
        data = endpoint(query)
        if 'errors' in data:
            raise Exception("Invalid data response", data['errors'])

        consignments = (query + data).consignments
        has_next_page = consignments.page_info.has_next_page
        consignments_dict = [node_to_dict(edge.node) for edge in consignments.edges]
        all_consignments.extend(consignments_dict)
        current_cursor = consignments.edges[-1].cursor if len(consignments.edges) > 0 else None
        print("Total consignments: ", len(all_consignments))

    # create_directory()
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = [
            "ConsignmentReference", "ConsignmentType", "TransferringBodyName", "BodyCode",
            "SeriesCode", "ConsignmentId", "UserId", "CreatedDateTime", "TransferInitiatedDatetime", "ExportDateTime",
            "ExportLocation", "FileCount", "TotalSize(Bytes)"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_consignments)
    slack(event['emails'])


def slack(emails):
    slack_bot_token = decode("SLACK_BOT_TOKEN")
    client = WebClient(token=slack_bot_token)
    print("sending report - ", emails)
    for email in emails:
        user_data = client.users_lookupByEmail(email=email)
        with open(csv_file_path, 'rb') as csvfile:
            client.files_upload(file=csvfile, channels=[user_data["user"]["id"]])


# noinspection PyBroadException
def handler(event=None, context=None):
    try:
        generate_report(event)
    except Exception:
        traceback.print_exc()
        return {
            "statusCode": 500
        }
