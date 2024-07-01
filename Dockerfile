FROM amazonlinux:2.0.20240610.1
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh /
COPY reporting /app
RUN ./build-dependencies.sh
