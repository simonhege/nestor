# Copilot Instructions for Nestor

## Project Overview
Nestor is a simple account manager for web applications that provides OpenID Connect (OIDC) authentication. It allows users to connect via local accounts or third-party OIDC providers (Google, Azure AD).

## Architecture
- **Language**: Go 1.24.6+
- **Web Framework**: Custom server using `github.com/simonhege/server`
- **Authentication**: OIDC with PKCE (Proof Key for Code Exchange)
- **Storage**: Supports in-memory (development) and Couchbase (production)
- **Deployment**: Dockerized serverless application

## Development Setup

### Prerequisites
- Go 1.24.6 or higher
- Docker (for containerized deployment)

### Local Development
1. Install dependencies: `go install`
2. Create a `.env` file with required environment variables:
   ```env
   BASE_URL=http://localhost:9021
   PORT=9021
   ISSUER=http://localhost:9021/
   DEBUG_TEMPLATES=Y
   ```
3. Run the application: `nestor`

### Building
- Standard Go build: `go build`
- Docker build: `docker build -t nestor .`

### Linting
- Linter: golangci-lint v2.4
- Run: `golangci-lint run`
- CI runs linter automatically on PRs and pushes to main

### Testing
- No test files currently exist in the repository
- When adding tests, follow Go testing conventions with `*_test.go` files

## Code Conventions

### Error Handling
- Use structured logging with `log/slog` for all errors
- Log context-aware messages: `slog.ErrorContext(ctx, "message", "key", value)`
- Log levels: Info for normal operations, Warn for recoverable issues, Error for failures
- Always handle errors explicitly; don't ignore them

### Logging
- Use `log/slog` for all logging (not `fmt.Println` or `log.Print`)
- Include context in log calls: `slog.InfoContext(ctx, "message")`
- Add relevant attributes as key-value pairs
- Log warnings for configuration issues (e.g., using in-memory store)

### HTTP Handlers
- Use standard `http.ResponseWriter` and `http.Request` parameters
- Extract context from request: `ctx := req.Context()`
- Return appropriate HTTP status codes
- Log errors before returning HTTP error responses
- Use `http.Error()` for error responses

### Configuration
- Read from environment variables using `os.Getenv()`
- Use `cmp.Or()` for default values (Go 1.24+ feature)
- Load `.env` file for local development using `github.com/joho/godotenv`
- Configuration is client-specific and can be customized via environment variables

### Code Style
- Follow standard Go conventions
- Use meaningful variable names
- Keep functions focused and single-purpose
- Use interfaces for storage abstractions (e.g., `account.Store`, `privatekeys.Store`)

## Project Structure
- `main.go` - Application entry point and server setup
- `app.go` - Application struct and core methods
- `account/` - Account management logic and storage interfaces
- `connector/` - OIDC provider connectors
- `csrf/` - CSRF protection
- `privatekeys/` - Private key management
- `signed/` - Signed token utilities
- `stores/` - Storage implementations (memory, couchbase)
- `templates/` - HTML templates for login pages

## Key Features to Understand
1. **OIDC Flow**: Authorization Code Grant with PKCE
2. **Multi-provider**: Supports local accounts and external OIDC providers
3. **Account Linking**: Can link multiple external providers to one account
4. **Secure**: Uses bcrypt for password hashing, JWT for tokens

## When Making Changes
- Maintain backward compatibility for existing OIDC clients
- Ensure proper error logging with context
- Update environment variable documentation if adding new config
- Consider both in-memory and Couchbase storage implementations
- Test manually with a running instance for UI/flow changes
- Preserve security features (PKCE, CSRF protection, password hashing)

## Dependencies
- Add new dependencies carefully; prefer standard library when possible
- Update `go.mod` and `go.sum` with `go mod tidy`
- Key dependencies:
  - `github.com/golang-jwt/jwt/v5` - JWT tokens
  - `github.com/coreos/go-oidc/v3` - OIDC client
  - `golang.org/x/crypto` - Password hashing
  - `github.com/couchbase/gocb/v2` - Couchbase client

## CI/CD
- **Lint**: golangci-lint runs on all PRs and main branch pushes
- **Build**: Docker build runs on all PRs; pushes on tags
- **Deploy**: Automatic deployment to Scaleway on version tags
