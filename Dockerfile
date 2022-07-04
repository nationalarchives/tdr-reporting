FROM amazonlinux
COPY requirements-runtime.txt /requirements.txt
COPY build-dependencies.sh /
COPY reporting /app
RUN ./build-dependencies.sh
