.PHONY: build test fmt lint keycreator signer

all: build test fmt lint

build:
	go build ./...

test:
	go test ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

keycreator:
	rm -f cmd/keycreator/keycreator
	cd cmd/key-creator && go build .
	./cmd/key-creator/key-creator --config config/keycreator.toml

signer:
	rm -f cmd/signer/signer
	cd cmd/signer && go build .
	./cmd/signer/signer --config config/signer.toml