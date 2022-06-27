import io
import json
import urllib
from unittest.mock import patch

import boto3
import pandas as pandas
import pandas as pd
import pytest
from moto import mock_kms
from nose.tools import eq_

from reporting import report
from utils.utils import *

csv_file_path = "../generated_report/report.csv"
timeout = 300
graphql_query = """
query {
  consignments(limit: 100, currentCursor: null) {
    edges {
      node {
        consignmentid
        consignmentType
        consignmentReference
        userid
        exportDatetime
        exportLocation
        createdDatetime
        transferringBody {
            name
            tdrCode
        }
        files {
            fileId
            metadata {
              clientSideFileSize
            }
        }
        series {
            code
            name
        }
      }
      cursor
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}"""

graphql_response_ok = b'''
{
  "data": {
    "consignments": {
      "edges": [
          {"node": {"series": null, "exportDatetime": null, "exportLocation": null, "userid": "9ae3d9c5-8a71-4c50-9b19-b1ff4d315b70", "files": [], "transferringBody": {"name": "MOCK1 Department", "tdrCode": "MOCK1"}, "consignmentid": "71c95054-74c1-4419-8864-67046c7fbbc7", "consignmentReference": "TDR-2022-C", "createdDatetime": "2022-05-10T11:43:19Z", "consignmentType": "judgment"}, "cursor": "TDR-2022-C"}
      ],
      "pageInfo": {"hasNextPage": false, "endCursor": "TDR-2022-C"}
    }
  }
}'''

graphql_response_json_error = b'''
{
  "data": {
    "consignments": {
      "edges": [
          {"node": {"series": null, "exportDatetime": null, "exportLocation": null, "userid": "9ae3d9c5-8a71-4c50-9b19-b1ff4d315b70", "files": [, "transferringBody": {"name": "MOCK1 Department", "tdrCode": "MOCK1"}, "consignmentid": "71c95054-74c1-4419-8864-67046c7fbbc7", "consignmentReference": "TDR-2022-C", "createdDatetime": "2022-05-10T11:43:19Z", "consignmentType": "judgment"}, "cursor": "TDR-2022-C"}
      ],
      "pageInfo": {"hasNextPage": false, "endCursor": "TDR-2022-C"}
    }
  }
}'''

graphql_response_missing_required_fields = b'''
{
  "data": {
    "consignments": {
      "edges": [
          {"node": {"series": null, "exportDatetime": null, "exportLocation": null, "files": [], "transferringBody": {"name": "MOCK1 Department", "tdrCode": "MOCK1"}, "consignmentid": "71c95054-74c1-4419-8864-67046c7fbbc7", "consignmentReference": "TDR-2022-C", "createdDatetime": "2022-05-10T11:43:19Z", "consignmentType": "judgment"}, "cursor": "TDR-2022-C"}
      ],
      "pageInfo": {"hasNextPage": false, "endCursor": "TDR-2022-C"}
    }
  }
}'''


def configure_mock_urlopen(mock_urlopen, payload):
    if isinstance(payload, Exception):
        mock_urlopen.side_effect = payload
    else:
        mock_urlopen.return_value = io.BytesIO(payload)


def remove_csv():
    if os.path.exists(csv_file_path):
        os.remove(csv_file_path)


def check_request_headers_(req, headers, name):
    if not headers:
        return
    if isinstance(headers, dict):
        headers = headers.items()
    for k, v in headers:
        g = req.get_header(k)
        eq_(g, v, 'Failed {} header {}: {!r} != {!r}'.format(name, k, v, g))


def check_request_headers(req, base_headers):
    accept_header = 'application/json; charset=utf-8'
    eq_(req.get_header('Accept'), accept_header)
    if req.method == 'POST':
        eq_(req.get_header('Content-type'), 'application/json; charset=utf-8')
    check_request_headers_(req, base_headers, 'base')


def get_request_url_query(req):
    split = urllib.parse.urlsplit(req.full_url)
    query = urllib.parse.parse_qsl(split.query)
    if isinstance(query, list):
        query = dict(query)
    return query


def check_request_query(req, query):
    if req.method == 'POST':
        post_data = json.loads(req.data)
        received = post_data.get('query')
    else:
        query_data = get_request_url_query(req)
        received = query_data.get('query')

    if isinstance(query, bytes):
        query = query.decode('utf-8')

    query = "\n".join([s.strip() for s in query.split("\n") if s])
    eq_(received, query)


def check_mock_urlopen(mock_urlopen,
                       method='POST',
                       base_headers=None,
                       query=None,  # defaults to `graphql_query`
                       ):
    assert mock_urlopen.called
    args = mock_urlopen.call_args
    req = args[0][0]
    eq_(req.method, method)
    eq_(args[1]['timeout'], timeout)
    check_request_headers(req, base_headers)
    check_request_query(req, query or graphql_query)


@pytest.fixture(scope='function')
def kms():
    with mock_kms():
        yield boto3.client('kms', region_name='eu-west-2')


@patch('urllib.request.urlopen')
def test_report_with_valid_response(mock_urlopen, kms):
    """Test if it generates report.csv with valid graphql response"""

    with patch('reporting.report.requests.post') as mock_post:
        set_up(kms)
        configure_mock_urlopen(mock_urlopen, graphql_response_ok)
        mock_post.return_value.status_code = 200
        mock_post.return_value.json = access_token
        report.handler()
        df = pandas.read_csv(csv_file_path)
        assert len(df) == 1
        assert df['ConsignmentReference'][0] == 'TDR-2022-C'
        assert df['ConsignmentType'][0] == 'judgment'
        assert df['TransferringBodyName'][0] == 'MOCK1 Department'
        assert df['BodyCode'][0] == 'MOCK1'
        assert pd.isnull(df['SeriesCode'][0]) is True
        assert df['ConsignmentId'][0] == '71c95054-74c1-4419-8864-67046c7fbbc7'
        assert df['UserId'][0] == '9ae3d9c5-8a71-4c50-9b19-b1ff4d315b70'
        assert df['CreatedDateTime'][0] == '2022-05-10T11:43:19Z'
        assert pd.isna(df['TransferInitiatedDatetime'][0]) is True
        assert pd.isna(df['ExportDateTime'][0]) is True
        assert pd.isna(df['ExportLocation'][0]) is True
        assert df["FileCount"][0] == 0
        assert df['TotalSize(Bytes)'][0] == 0

    remove_csv()


@patch('urllib.request.urlopen')
def test_json_error(mock_urlopen, kms):
    """Test if broken server responses (invalid JSON) is handled"""

    with patch('reporting.report.requests.post') as mock_post:
        set_up(kms)
        configure_mock_urlopen(mock_urlopen, graphql_response_json_error)
        mock_post.return_value.status_code = 200
        mock_post.return_value.json = access_token
        response = report.handler()
        assert response['statusCode'] == 500


@patch('urllib.request.urlopen')
def test_missing_required_field(mock_urlopen, kms):
    """Test if incorrect server responses (missing required fields) is handled"""

    with patch('reporting.report.requests.post') as mock_post:
        set_up(kms)
        configure_mock_urlopen(mock_urlopen, graphql_response_missing_required_fields)
        mock_post.return_value.status_code = 200
        mock_post.return_value.json = access_token
        response = report.handler()
        assert response['statusCode'] == 500


@patch('urllib.request.urlopen')
def test_headers_and_query(mock_urlopen, kms):
    """Test if all headers, query and standard timeout are passed"""

    with patch('reporting.report.requests.post') as mock_post:
        set_up(kms)
        configure_mock_urlopen(mock_urlopen, graphql_response_ok)
        mock_post.return_value.status_code = 200
        mock_post.return_value.json = access_token
        report.handler()
        headers = {'Authorization': f'Bearer {access_token()["access_token"]}'}
        check_mock_urlopen(mock_urlopen, base_headers=headers)


@patch('urllib.request.urlopen')
def test_http_server_error(mock_urlopen, kms):
    """Test if HTTP error without JSON payload is handled"""

    with patch('reporting.report.requests.post') as mock_post:
        set_up(kms)

        err = urllib.error.HTTPError(
            'http://testserver.com',
            500,
            'Some Error',
            {'Xpto': 'abc'},
            io.BytesIO(b'xpto'),
        )
        configure_mock_urlopen(mock_urlopen, err)
        mock_post.return_value.status_code = 200
        mock_post.return_value.json = access_token
        response = report.handler()
        assert response['statusCode'] == 500
