default: check build

format:
    gofmt -w .

lint:
    test -z "$(gofmt -l .)"
    go vet ./...

test:
    go test ./...

check: lint test

build:
    go build -o markov-canary .

serve: build
    ./markov-canary serve
