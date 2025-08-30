APP := pentakit

.PHONY: build run test tidy

build:
	go build -o bin/$(APP) ./cmd/main

run:
	go run ./cmd/pentakit --help

test:
	go test ./...

tidy:
	go mod tidy