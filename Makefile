APP       := detector
BUILD_DIR := build
MAIN_PKG  := ./cmd/detector
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFLAGS   := -trimpath
CONFIG    ?= config.toml
WEB_DIR   := web
WEB_EMBED := internal/webui/dist
# NOWEB=1 skips the web build and embeds whatever is already in $(WEB_EMBED)
NOWEB     ?=

export CGO_ENABLED := 0

.PHONY: all build build-linux-amd64 build-linux-arm64 build-linux generate web run start dev-web test vet clean help

all: build-linux

## build: 현재 OS/ARCH 용 빌드 (웹 UI 포함 단일 바이너리)
build: generate web
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP) $(MAIN_PKG)

## build-linux-amd64: linux/amd64 빌드
build-linux-amd64: generate web
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP)-linux-amd64 $(MAIN_PKG)

## build-linux-arm64: linux/arm64 빌드
build-linux-arm64: generate web
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP)-linux-arm64 $(MAIN_PKG)

## build-linux: linux amd64 + arm64 모두 빌드
build-linux: build-linux-amd64 build-linux-arm64

## generate: OpenAPI 스펙으로부터 서버 코드 생성 (oapi-codegen)
generate:
	go generate ./api/...

## web: React 빌드(.env.production) 후 바이너리 임베드 위치로 복사
web:
ifeq ($(NOWEB),)
	@test -d $(WEB_DIR)/node_modules || (cd $(WEB_DIR) && npm ci)
	cd $(WEB_DIR) && npm run build
	find $(WEB_EMBED) -mindepth 1 ! -name .gitkeep -delete
	cp -R $(WEB_DIR)/dist/. $(WEB_EMBED)/
else
	@echo "NOWEB=1: skip web build"
endif

## run: 빌드 후 실행 → http://localhost:<apiPort>/detector/ (CONFIG=config.toml)
run: build
	./$(BUILD_DIR)/$(APP) -c $(CONFIG)

## start: 빌드 후 실행하고 브라우저 열기
start: build
	./$(BUILD_DIR)/$(APP) -c $(CONFIG) -open

## dev-web: UI 개발용 Vite 서버 (핫 리로드, /api 는 web/.env.development 의 VITE_PROXY_TARGET 으로 프록시)
dev-web:
	cd $(WEB_DIR) && npm run dev

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
