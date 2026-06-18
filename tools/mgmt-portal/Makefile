.PHONY: build web docker dev

web:
	cd web && npm install && npm run build

build: web
	go build -o bin/mgmt-portal ./cmd/mgmt-portal

docker: web
	docker build -t 5gc/mgmt-portal:dev -f Dockerfile .

dev:
	@echo "Start vite dev server in one terminal: cd web && npm run dev"
	@echo "Start Go server in another terminal:    go run ./cmd/mgmt-portal"
