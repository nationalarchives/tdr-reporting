import sys
import report

report.handler({"emails": sys.argv[2:], "report": sys.argv[1]})
