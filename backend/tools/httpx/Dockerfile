FROM golang:alpine AS builder

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx

ENTRYPOINT ["httpx"]
