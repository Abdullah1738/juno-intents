# syntax=docker/dockerfile:1.7

FROM --platform=linux/amd64 golang:1.22.6-bookworm@sha256:0fb1bda119f4cc07d236c2b98225d1ef0cb6e759a407d5d6d09e58402643679f AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -trimpath -buildvcs=false -mod=readonly -ldflags "-s -w -buildid=" -o /out/operator ./cmd/nitro-operator-enclave

FROM scratch

COPY --from=builder /out/operator /operator
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/operator"]

