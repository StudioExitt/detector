APP       := detector
BUILD_DIR := build
MAIN_PKG  := ./cmd/detector
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFLAGS   := -trimpath
CONFIG    ?= config.toml

export CGO_ENABLED := 0

.PHONY: all build build-linux-amd64 build-linux-arm64 build-linux generate run test vet clean help

all: build-linux

## build: 현재 OS/ARCH 용 빌드
build: generate
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP) $(MAIN_PKG)

## build-linux-amd64: linux/amd64 빌드
build-linux-amd64: generate
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP)-linux-amd64 $(MAIN_PKG)

## build-linux-arm64: linux/arm64 빌드
build-linux-arm64: generate
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP)-linux-arm64 $(MAIN_PKG)

## build-linux: linux amd64 + arm64 모두 빌드
build-linux: build-linux-amd64 build-linux-arm64

## generate: OpenAPI 스펙으로부터 서버 코드 생성 (oapi-codegen)
generate:
	go generate ./api/...

## run: 로컬 실행 (CONFIG=config.toml)
run: generate
	go run $(MAIN_PKG) -c $(CONFIG)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
