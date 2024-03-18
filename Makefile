# VERSION is the version we should download and use.
VERSION:=$(shell git describe --match=NeVeRmAtCh --always --dirty)

BINARY_NAME:=acme
GOFLAGS:=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: $(BINARY_NAME) lambda

$(BINARY_NAME): test
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $@ $(GOFLAGS) ./cmd/cli

lambda: test
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bootstrap -tags lambda.norpc $(GOFLAGS) ./cmd/lambda
	zip acme.zip bootstrap

.PHONY: test
test: $(PROTOS)
	go test -test.short ./...

