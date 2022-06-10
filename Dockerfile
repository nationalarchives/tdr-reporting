FROM amazonlinux
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh reporting/report.py /
RUN ./build-dependencies.sh
