FROM python:3.14-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
  && pip install --no-cache-dir /opt/theHarvester

WORKDIR /opt/theHarvester
ENTRYPOINT ["theHarvester"]
