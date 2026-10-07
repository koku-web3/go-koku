.PHONY: build test fmt lint tidy

all: build test fmt lint

build:
	go build ./...

test:
	go test ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

tidy:
	go mod tidy