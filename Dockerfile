FROM golang:alpine
EXPOSE 2020

COPY pubkeyd.go /tmp/pubkeyd/

WORKDIR /tmp/pubkeyd
RUN apk add --no-cache tini git \
    && go get github.com/fatz/ghpubkey-go/ghpubkey \
    && go get github.com/gorilla/mux \
    && go get github.com/op/go-logging \
    && go get github.com/oswell/onelogin-go \
    && go build \
    && cp pubkeyd /sbin/ \
    && rm -rf /tmp/pubkeyd
WORKDIR /root

ENTRYPOINT ["/sbin/tini", "--", "/sbin/pubkeyd"]
