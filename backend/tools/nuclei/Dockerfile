FROM golang:alpine AS builder

RUN apk add --no-cache git \
  && GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM alpine:3.21

COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei

RUN apk add --no-cache ca-certificates

ENTRYPOINT ["nuclei"]
