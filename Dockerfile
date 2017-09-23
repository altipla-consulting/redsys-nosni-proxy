
FROM golang:1.8
MAINTAINER Ernesto Alejo <ernesto@altiplaconsulting.com>

COPY . /go/src/proxy

RUN go install proxy/cmd/proxy

WORKDIR /go/src/proxy
CMD proxy
