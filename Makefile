.PHONY: build run clean test password secret-key

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
