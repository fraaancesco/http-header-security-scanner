.PHONY: build run swagger clean install-tools

BINARY_NAME=http-header-security-scanner
MAIN_PATH=./cmd/server

# Build con generazione Swagger automatica
build: swagger
	go build -o $(BINARY_NAME) $(MAIN_PATH)

# Solo generazione Swagger
swagger:
	swag init -g $(MAIN_PATH)/main.go -o docs

# Build e run
run: build
	./$(BINARY_NAME)

# Solo run (senza rebuild)
run-only:
	./$(BINARY_NAME)

# Pulisci build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf docs/

# Installa tool necessari
install-tools:
	go install github.com/swaggo/swag/cmd/swag@latest

# Rigenera tutto da zero
rebuild: clean build
