.PHONY: install migrate dev test build

install:
	cd web && npm ci
	cd backend && go mod download

migrate:
	cd backend && go run . migrate

dev:
	node scripts/dev.mjs

test:
	cd backend && go test ./...
	cd web && npm test

build:
	cd backend && go build ./...
	cd web && npm run build
