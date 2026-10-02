.PHONY: build run swagger clean test coverage install-hscan install-skill

BINARY_NAME=http-header-security-scanner
MAIN_PATH=./cmd/server

# Build con generazione Swagger automatica
build: swagger
	go build -o $(BINARY_NAME) $(MAIN_PATH)

# Solo generazione Swagger
swagger:
	go tool swag init -g $(MAIN_PATH)/main.go -o docs

# Build e run
run: build
	./$(BINARY_NAME)

# Solo run (senza rebuild)
run-only:
	./$(BINARY_NAME)

# Test (docs/ è generato e senza test: viene comunque misurato tramite -coverpkg)
TEST_PKGS=$$(go list ./... | grep -v /docs)

test:
	go test -race -count=1 $(TEST_PKGS)

# Test con coverage: fallisce se sotto il 100%
coverage:
	go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out $(TEST_PKGS)
	@go tool cover -func=coverage.out | tail -1
	@go tool cover -func=coverage.out | tail -1 | grep -q '100.0%' || (echo "Coverage sotto il 100%" && exit 1)

# Pulisci build artifacts
clean:
	rm -f $(BINARY_NAME) coverage.out
	rm -rf docs/

# Installa la CLI hscan in $(go env GOPATH)/bin
install-hscan:
	go install ./cmd/hscan

# Installa la skill header-scan per tutti i progetti (~/.claude/skills)
install-skill:
	mkdir -p $(HOME)/.claude/skills
	cp -r .claude/skills/header-scan $(HOME)/.claude/skills/

# Rigenera tutto da zero
rebuild: clean build
