# Built from source: the official ghcr.io/owasp-amass/amass image needs registry
# access that is blocked on some networks (403 on anonymous pull).
FROM golang:alpine AS build
RUN apk add --no-cache git \
    && go install -v github.com/owasp-amass/amass/v5/cmd/amass@latest

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/amass /usr/local/bin/amass

ENTRYPOINT ["amass"]
