.PHONY: build test clean

BINARY=pdf-signer
BUILD_DIR=bin

build:
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/pdf-signer

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/pdf-signer

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/pdf-signer

test:
	go test -v ./...

clean:
	rm -rf $(BUILD_DIR)
