BINARY := swarf
BIN_DIR := .
CMD := ./cmd/swarf

VERSION := $(shell awk -F'"' '/"version":/ {print $$4}' version.json)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE := $(shell date -u -Iseconds)
GOFLAGS := -ldflags="-X github.com/fil-forge/swarf/pkg/build.version=$(VERSION) -X github.com/fil-forge/swarf/pkg/build.Commit=$(COMMIT) -X github.com/fil-forge/swarf/pkg/build.Date=$(DATE) -X github.com/fil-forge/swarf/pkg/build.BuiltBy=make"

.PHONY: build test vet clean gen

build:
	GOWORK=off go build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD)

gen:
	GOWORK=off go generate ./...

test:
	GOWORK=off go test ./...

vet:
	GOWORK=off go vet ./...

clean:
	rm -f $(BIN_DIR)/$(BINARY)
