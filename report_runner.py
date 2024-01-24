import sys
from reporting import report

report.handler({"userName": sys.argv[2], "reportType": sys.argv[1]})

