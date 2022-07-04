FROM amazonlinux
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh reporting /
RUN ./build-dependencies.sh
