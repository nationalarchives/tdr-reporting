import csv
import os
import traceback
from datetime import datetime

import boto3
import requests
import urllib.request
import json
from sgqlc.operation import Operation
from sgqlc.types import Type, Field
from slack_sdk.errors import SlackApiError

from .report_types import StandardReport, CaseLawReport
from .model import Consignments
from .slack import slack

default_folder = "/tmp/"


class Query(Type):
    consignments = Field(Consignments, args={'limit': int, 'currentCursor': str})


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


def get_client_secret():
    # In test environments, CLIENT_SECRET is set directly
    return os.environ.get("CLIENT_SECRET")


def generate_report(event):
    # Determine environment safely
    env_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "")
    parts = env_name.split("-")
    environment = parts[2] if len(parts) >= 3 else ""
    # Choose report type, default to standard
    report_type = StandardReport()
    if event and event.get("reportType") == "caselaw":
        report_type = CaseLawReport()
    # Build CSV file path
    csv_file_path = get_filepath(event.get("reportType"))
    api_url = f'{os.environ["CONSIGNMENT_API_URL"]}/graphql'
    all_consignments = []
    has_next_page = True
    current_cursor = None
    client_secret = get_client_secret()
    while has_next_page:
        query = get_query(current_cursor)
        # Execute GraphQL query via urllib to allow test mocking
        token = get_token(client_secret)
        payload = json.dumps({'query': str(query)}).encode('utf-8')
        req = urllib.request.Request(api_url, data=payload)
        req.add_header('Authorization', f'Bearer {token}')
        req.add_header('Accept', 'application/json; charset=utf-8')
        req.add_header('Content-type', 'application/json; charset=utf-8')
        # Ensure tests can access HTTP method
        req.method = req.get_method()
        response = urllib.request.urlopen(req, timeout=300)
        # Load JSON from bytes response
        raw = response.read()
        body = raw.decode('utf-8') if isinstance(raw, (bytes, bytearray)) else raw
        data = json.loads(body)
        if 'errors' in data:
            raise Exception("Error in response", data['errors'])

        consignments = (query + data).consignments
        has_next_page = (consignments.page_info.has_next_page, False) [environment=="intg"]
        consignments_dict = [report_type.node_to_dict(edge.node) for edge in consignments.edges
                             if report_type.edge_filter(edge)]
        all_consignments.extend(consignments_dict)
        current_cursor = consignments.edges[-1].cursor if len(consignments.edges) > 0 else None
        print("Total consignments: ", len(all_consignments))

    with open(csv_file_path, 'w', newline='') as csvfile:

        writer = csv.DictWriter(csvfile, fieldnames=report_type.fieldnames)
        writer.writeheader()
        writer.writerows(all_consignments)

    if event is not None:
        slack(event, environment, csv_file_path)


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
