.PHONY: build run clean test password secret-key

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/abcdlsj/nexo/internal/buildinfo.Version=$(VERSION) \
           -X github.com/abcdlsj/nexo/internal/buildinfo.Commit=$(COMMIT) \
           -X github.com/abcdlsj/nexo/internal/buildinfo.Date=$(BUILD_DATE)

# Build the application
build:
	go build -ldflags "-s -w $(LDFLAGS)" -o nexo

# Run the application
run: build
	./nexo server

# Clean build artifacts
clean:
	rm -f nexo

# Run tests
test:
	go test -v ./...

# Generate bcrypt password hash for WebUI without exposing the password in the
# process list or shell history.
password:
	@printf "Password: "; \
	stty -echo; \
	IFS= read -r password; status=$$?; \
	stty echo; printf "\n"; \
	[ $$status -eq 0 ] && [ -n "$$password" ] || exit 1; \
	htpasswd -bnBC 10 "" "$$password" | tr -d ':\n'; \
	printf "\n"

# Generate secret key for OAuth session signing
# Usage: make secret-key
secret-key:
	@openssl rand -base64 32
