lint:
	golangci-lint run

down:
	docker-compose down --volumes

start:
	docker-compose up --build -d


db-start:
	docker-compose up --build -d postgres

migration:
	@read -p "migration file name:" module; \
	cd internal/app/db/migrations && ~/go/bin/goose create $$module sql