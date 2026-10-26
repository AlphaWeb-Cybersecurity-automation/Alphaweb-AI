FROM python:3.13-slim

# subdominator (RevoltSecurities) needs Python >= 3.13. The runner appends -d <domain>.
RUN pip install --no-cache-dir subdominator

ENTRYPOINT ["subdominator"]
