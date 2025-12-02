APP := pentakit

.PHONY: build run test tidy lint vet fmt check

build:
	go build -o bin/$(APP) ./cmd/main

run:
	go run ./cmd/pentakit --help

test:
	go test ./...

tidy:
	go mod tidy

lint:
	golangci-lint run

vet:
	go vet ./...

fmt:
	go fmt ./...

check: fmt vet lint test