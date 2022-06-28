# TDR Reporting
This will generate a csv report of all consignments for the given environment.

### Setting up the environment
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running the report
This report needs AWS credentials with SSM access to work. These can be set with environment variables, in `~/.aws/credentials` or using sso profiles.

You need to also setup following environment variables if you are running from IntelliJ IDEA or you need to pass with python command:

1. AUTH_URL - For authentication. ie. `https://auth.tdr-integration.nationalarchives.gov.uk`
2. AWS_LAMBDA_FUNCTION_NAME - Use reporting lambda function name. ie. `tdr-reporting-intg`
3. CLIENT_ID - It should be `tdr-reporting`
4. CLIENT_SECRET - It should be encrypted client secret of `tdr-reporting` user
5. CONSIGNMENT_API_URL - Consignment API base url (https://api.tdr-integration.nationalarchives.gov.uk). If you are running locally then it should be `http://localhost:8080`.
6. AWS_DEFAULT_REGION -  AWS region `eu-west-2`

Once these are set you can run report_runner.py from IntelliJ IDEA or run with following command:
```bash
python report_runner.py <environment_variables>
```

It will create a file called report.csv in the `generated_report` directory.

### Cleaning up
```bash
deactivate
rm -r venv
```
