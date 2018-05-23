FROM golang:alpine
EXPOSE 2020

COPY . /go/src/pubkeyd/

WORKDIR /go/src/pubkeyd
RUN apk add --no-cache tini \
    && go build \
    && cp pubkeyd /sbin/
WORKDIR /root

ENTRYPOINT ["/sbin/tini", "--", "/sbin/pubkeyd"]
