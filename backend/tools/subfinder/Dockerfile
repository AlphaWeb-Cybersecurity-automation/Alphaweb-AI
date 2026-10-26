
FROM golang:alpine AS build
RUN apk add --no-cache git \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/subfinder /usr/local/bin/subfinder
# -d <domain> is appended by the runner; -silent keeps output to bare hostnames.
ENTRYPOINT ["subfinder", "-silent"]
