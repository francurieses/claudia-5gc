# nf/nrf/Makefile
.PHONY: build test test-cover test-functional lint docker run clean

NF := nrf
BIN := bin/$(NF)
PKG := ./...

build:
	@mkdir -p bin
	go build -o $(BIN) ./cmd/$(NF)

# Gate de CI: solo correctness. No usa -coverprofile porque el toolchain
# modular de Go 1.26 no trae el binario covdata (necesario para escribir
# cobertura de paquetes sin tests). Para cobertura local: make test-cover.
test:
	go test -race $(PKG)

test-cover:
	go test -race -cover -coverprofile=coverage.out $(PKG)

test-functional:
	@if [ -d tests/features ]; then \
		go test -tags=functional ./tests/features/... ; \
	else \
		echo "no features dir"; \
	fi

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

docker:
	cd ../.. && docker build -f nf/$(NF)/Dockerfile -t 5gc/$(NF):dev .

run: build
	CONFIG_PATH=$(PWD)/config/dev.yaml ./$(BIN)

clean:
	rm -rf bin coverage.out
