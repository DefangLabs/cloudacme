# VERSION is the version we should download and use.
VERSION:=$(shell git describe --match=NeVeRmAtCh --always --dirty)

BINARY_NAME:=cloudacme
GOFLAGS:=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: $(BINARY_NAME) $(BINARY_NAME)-lambda.zip

$(BINARY_NAME): test
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $@ $(GOFLAGS) ./cmd/cli

$(BINARY_NAME)-lambda.zip: test
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bootstrap -tags lambda.norpc $(GOFLAGS) ./cmd/lambda
	zip $(BINARY_NAME)-lambda.zip bootstrap

.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-lambda.zip bootstrap

.PHONY: test
test: $(PROTOS)
	go test -test.short ./...

