import csv
import os
import traceback
from datetime import datetime

import boto3
import requests
from sgqlc.endpoint.http import HTTPEndpoint
from sgqlc.operation import Operation
from sgqlc.types import Type, Field, list_of
from slack_sdk.errors import SlackApiError

from .report_types import StandardReport, CaseLawReport, FileCheckFailuresReport
from .model import Consignments, FileCheckFailure, GetFileCheckFailuresInput
from .slack import slack

default_folder = "/tmp/"


class Query(Type):
    consignments = Field(Consignments, args={'limit': int, 'currentCursor': str})
    getFileCheckFailures = Field(list_of(FileCheckFailure),
                                 args={'getFileCheckFailuresInput': GetFileCheckFailuresInput})


def get_token(client_secret):
    client_id = os.environ["CLIENT_ID"]
    auth_url = f'{os.environ["AUTH_URL"]}/realms/tdr/protocol/openid-connect/token'
    grant_type = {"grant_type": "client_credentials"}
    auth_response = requests.post(auth_url, data=grant_type, auth=(client_id, client_secret))
    print("Auth response", auth_response.status_code)
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
    node.totalFiles()
    node.totalFileSize()
    node.transferringBodyName()
    node.transferringBodyTdrCode()
    node.seriesName()
    edges.cursor()
    consignments_query.page_info.__fields__('has_next_page')
    consignments_query.page_info.__fields__(end_cursor=True)
    return operation


def get_file_check_failures_query(event):
    operation = Operation(Query)

    input_args = {}
    if event.get('consignmentId') and event['consignmentId'].strip():
        input_args['consignmentId'] = event['consignmentId']
    if event.get('startDateTime') and event['startDateTime'].strip():
        input_args['startDateTime'] = event['startDateTime']
    if event.get('endDateTime') and event['endDateTime'].strip():
        input_args['endDateTime'] = event['endDateTime']

    failures_query = operation.getFileCheckFailures(getFileCheckFailuresInput=input_args)
    failures_query.fileId()
    failures_query.consignmentId()
    failures_query.consignmentType()
    failures_query.rankOverFilePath()
    failures_query.PUID()
    failures_query.userId()
    failures_query.statusType()
    failures_query.statusValue()
    failures_query.seriesName()
    failures_query.transferringBodyName()
    failures_query.antivirusResult()
    failures_query.extension()
    failures_query.identificationBasis()
    failures_query.extensionMismatch()
    failures_query.formatName()
    failures_query.checksum()
    failures_query.createdDateTime()

    return operation


def get_client_secret():
    client_secret_path = os.environ["CLIENT_SECRET_PATH"]
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(
        Name=client_secret_path,
        WithDecryption=True
    )
    return response["Parameter"]["Value"]


def execute_query(query, client_secret, api_url):
    headers = {'Authorization': f'Bearer {get_token(client_secret)}'}
    endpoint = HTTPEndpoint(api_url, headers, 300)
    data = endpoint(query)

    if 'errors' in data:
        raise Exception("Error in response", data['errors'])

    return data


def write_csv_report(data_rows, fieldnames, csv_file_path):
    with open(csv_file_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data_rows)


def generate_file_check_failures_report(event):
    environment = os.environ["AWS_LAMBDA_FUNCTION_NAME"].split("-")[2]
    report_type = FileCheckFailuresReport()
    csv_file_path = get_filepath(event["reportType"])
    api_url = f'{os.environ["CONSIGNMENT_API_URL"]}/graphql'

    query = get_file_check_failures_query(event)
    client_secret = get_client_secret()
    data = execute_query(query, client_secret, api_url)

    failures = (query + data).getFileCheckFailures
    failures_dict = [report_type.failure_to_dict(failure) for failure in failures]

    print(f"Total file check failures: {len(failures_dict)}")

    write_csv_report(failures_dict, report_type.fieldnames, csv_file_path)

    if event is not None:
        slack(event, environment, csv_file_path)


def generate_consignments_report(event):
    environment = os.environ["AWS_LAMBDA_FUNCTION_NAME"].split("-")[2]

    report_type = StandardReport()
    if event is not None and event.get("reportType") == "caselaw":
        report_type = CaseLawReport()

    csv_file_path = get_filepath(event.get("reportType"))
    api_url = f'{os.environ["CONSIGNMENT_API_URL"]}/graphql'
    client_secret = get_client_secret()

    all_consignments = []
    has_next_page = True
    current_cursor = None

    while has_next_page:
        query = get_query(current_cursor)
        data = execute_query(query, client_secret, api_url)

        consignments = (query + data).consignments
        has_next_page = (consignments.page_info.has_next_page, False)[environment == "intg"]

        consignments_dict = [report_type.node_to_dict(edge.node) for edge in consignments.edges
                             if report_type.edge_filter(edge)]
        all_consignments.extend(consignments_dict)
        current_cursor = consignments.edges[-1].cursor if len(consignments.edges) > 0 else None
        print("Total consignments: ", len(all_consignments))

    write_csv_report(all_consignments, report_type.fieldnames, csv_file_path)

    if event is not None:
        slack(event, environment, csv_file_path)


def generate_report(event):
    report_type = event.get("reportType", "standard")

    if report_type == "fileCheckFailures":
        generate_file_check_failures_report(event)
    else:
        generate_consignments_report(event)


def get_filepath(reportType=None):
    report_type = (reportType, "standard")[not reportType]
    return f"{default_folder}report_{report_type}_{datetime.today().strftime('%Y%m%d')}.csv"


# noinspection PyBroadException
def handler(event=None, context=None):
    try:
        generate_report(event)
    except SlackApiError as e:
        return {
            "statusCode": 401,
            "Error": str(e)
        }
    except Exception:
        traceback.print_exc()
        return {
            "statusCode": 500
        }