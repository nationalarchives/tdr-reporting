# TDR Reporting
This will generate a csv report of all consignments for the given environment.

### Setting up the environment
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running the test locally
```bash
python -m pytest
```

### Running different report types.
There are three different reports available.
* Standard - this is the service owner report which gives a detailed report of all consignments.
* CaseLaw - this is a summary report with fewer fields than the standard report and is only for judgment consignments.
* fileCheckFailures - all files that have failed one or more automated file checks (e.g. antivirus, checksum, file format identification) during the transfer process.

### File check failures usage notes

#### Optional parameters

By default the report covers all consignments in the chosen environment. Two optional filters can be used to narrow the results.

- **Consignment ID**: Enter a consignment UUID in the **Consignment ID** field to restrict the report to a single consignment. Leave blank to include all consignments.
- **Date range**: Enter a start and end datetime in the **Start date** and **End date** fields to restrict the report to consignments within that period. Both fields must be provided together and must use the format `YYYY-MM-DDTHH:MM:SSZ`, for example `2026-01-01T00:00:00Z`. Leave both blank to include all dates.

#### Output column: rank_over_file_path

This column helps identify files that share the same file path within the file check failure results, while keeping the actual file paths anonymous. Rather than showing the path itself, it shows a number representing the file path's alphabetical rank among all file paths in the report results — so all files sharing the same path will have the same rank value. This makes it possible to spot duplicate paths without exposing the underlying file path data.

### Running the report locally
This report needs AWS credentials with SSM access to work. These can be set with environment variables, in `~/.aws/credentials` or using sso profiles.

You need to also setup following environment variables if you are running from IntelliJ IDEA or you need to pass with python command:

1. AUTH_URL - For authentication. ie. `https://auth.tdr-{environment}.nationalarchives.gov.uk`
2. AWS_LAMBDA_FUNCTION_NAME - Use reporting lambda function name. ie. `tdr-reporting-{environment}`
3. CLIENT_ID - It should be `tdr-reporting`
4. CLIENT_SECRET_PATH - Parameter store path of the client secret eg. `/{environment}/path/to/value`
5. CONSIGNMENT_API_URL - Consignment API base url (https://api.tdr-{environment}.nationalarchives.gov.uk). If you are running locally then it should be `http://localhost:8080`.
6. AWS_DEFAULT_REGION -  AWS region `eu-west-2`
7. SLACK_BOT_TOKEN - Should be encrypted value from {environment} SSM Parameter store
8. TDR_REPORTING_SLACK_CHANNEL_ID - Should be encrypted value from {environment} SSM Parameter store

To use the decrypted SLACK_BOT_TOKEN vale, set the environment variable LOCAL_DEV="true"   
Update slack.py adding the if condition to decode the token:
```
def decode(env_var_name):
    if "LOCAL_DEV" in os.environ:
        return os.environ[env_var_name]  # Return token directly
    client = boto3.client("kms")
```

You will need to provide a report type as the first argument, either standard or caselaw.

Once these are set you can run report_runner.py from IntelliJ IDEA or run with following command:
```bash
python report_runner.py <environment_variables> <report_type> username
```

It will create a file called report.csv in the `/tmp` directory and  will send a slack message to the `da-tdr-reporting` Slack channel. The username must be provided and enclosed in double quotes.

### Cleaning up
```bash
deactivate
rm -r venv
```
