.PHONY: build run clean test password

# Build the application
build:
	go build -o nexo

# Run the application
run: build
	./nexo server

# Clean build artifacts
clean:
	rm -f nexo

# Run tests
test:
	go test -v ./...

# Generate bcrypt password hash for WebUI
# Usage: make password PASSWORD=yourpassword
password:
	@if [ -z "$(PASSWORD)" ]; then \
		echo "Usage: make password PASSWORD=yourpassword"; \
		exit 1; \
	fi
	@htpasswd -bnBC 10 "" "$(PASSWORD)" | tr -d ':\n'
	@echo ""
