ARG src_dir="/go/src/github.com/cloudflare/cfrpki"

FROM golang:alpine as builder
ARG src_dir

RUN apk --update --no-cache add git && \
    mkdir -p ${src_dir}

WORKDIR ${src_dir}
COPY . .

RUN go get -u github.com/golang/dep/cmd/dep && \
    dep ensure && \
    go build cmd/octorpki/octorpki.go

FROM alpine:latest
ARG src_dir

RUN apk --update --no-cache add ca-certificates rsync && \
    adduser -S -D -H -h / rpki && \
    mkdir /cache && chmod 770 /cache && chown rpki:root /cache
USER rpki

COPY --from=builder ${src_dir}/octorpki ${src_dir}/cmd/octorpki/private.pem /
COPY --from=builder ${src_dir}/cmd/octorpki/tals /tals
ENTRYPOINT ["./octorpki"]
