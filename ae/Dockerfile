FROM python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        chromium \
        chromium-driver \
        curl \
        fonts-dejavu-core \
        fonts-liberation \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY ae/requirements.txt /tmp/semscanner-ae-requirements.txt
RUN python -m pip install --no-cache-dir \
        --requirement /tmp/semscanner-ae-requirements.txt \
    && rm /tmp/semscanner-ae-requirements.txt

WORKDIR /opt/semscanner
COPY . /opt/semscanner

RUN chmod 0755 /opt/semscanner/ae/container-entrypoint.sh \
    && python -m compileall -q /opt/semscanner

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/semscanner \
    CHROME_BINARY=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver \
    SEMSCANNER_ATTACK_MAX_WORKERS=1 \
    SEMSCANNER_ATTACK_TASK_TIMEOUT_XSS=300 \
    SEMSCANNER_XSS_BEACON_URL=http://127.0.0.1:9091/

LABEL org.opencontainers.image.title="SemScanner AE Runtime" \
      org.opencontainers.image.description="Containerized SemScanner runtime for artifact evaluation" \
      org.opencontainers.image.version="dev"

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/semscanner/ae/container-entrypoint.sh"]
CMD ["doctor"]
