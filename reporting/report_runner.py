import sys
import report

report.handler({"emails": sys.argv[1:]})
