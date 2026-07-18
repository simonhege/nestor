# Nestor

Nestor is a lightweight OpenID Connect (OIDC) provider for web applications.

It lets your application delegate authentication to external identity providers (such as Google or Microsoft), then issues tokens from your own issuer domain.

## Overview

Nestor currently provides:

- OIDC discovery and JWKS endpoints.
- Authorization Code flow with PKCE.
- Token issuance (`access_token`, `id_token`, optional `refresh_token`).
- External login connectors:
	- Google
	- Microsoft
- Account persistence with:
	- In-memory store (development)
	- Couchbase store

Nestor also supports local password login on the authorize page for accounts that already have a password hash in storage.

## Implemented Endpoints

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /authorize`
- `POST /authorize`
- `POST /token`
- `GET /{connector}/login`
- `GET /{connector}/callback`
- `DELETE /accounts/me`

## Authorization Code + PKCE Flow

1. Your client app redirects the user to `GET /authorize` with standard OAuth parameters (`client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method`).
2. Nestor renders a login page.
3. The user authenticates either:
	 - with an external connector (Google/Microsoft), or
	 - with local email/password (if the account exists and has a password hash).
4. Nestor creates a short-lived authorization record.
5. Nestor redirects back to your `redirect_uri` with `code` and `state`.
6. Your client calls `POST /token` with `grant_type=authorization_code`, `client_id`, `code`, and `code_verifier`.
7. Nestor validates PKCE and returns tokens.
8. If `offline_access` was granted, Nestor also returns a refresh token.

## Requirements

- Go `1.26+`
- (Optional) Couchbase if you do not use in-memory storage

## Quick Start (Local Development)

1. Install dependencies:

```bash
go mod download
```

2. Create a `.env` file in the project root (example below).

3. Run the server:

```bash
go run .
```

The server listens on `http://localhost:9021` by default.

### Minimal `.env` Example

This example uses:

- in-memory datastore,
- one client configuration,
- Google as connector.

```env
BASE_URL=http://localhost:9021
ISSUER=http://localhost:9021/
PORT=9021
DEBUG_TEMPLATES=Y

NESTOR_CLIENT_ID=my-client
NESTOR_REDIRECT_URIS=http://localhost:3000/callback
NESTOR_DEFAULT_RESOURCE_INDICATOR=my-api

NESTOR_CONNECTOR_GOOGLE_CLIENT_ID=your-google-client-id
NESTOR_CONNECTOR_GOOGLE_CLIENT_SECRET=your-google-client-secret
```

If `COUCHBASE_CONNECTION_STRING` is not set, Nestor automatically uses in-memory storage.

## Configuration Reference

### Core

| Variable | Required | Description |
| --- | --- | --- |
| `BASE_URL` | No | Public base URL used for callback and endpoint generation. Default: `http://localhost:9021` |
| `ISSUER` | Yes (recommended) | OIDC issuer value returned in discovery and used in tokens |
| `PORT` | No | HTTP server port. Default: `9021` |
| `DEBUG_TEMPLATES` | No | Set to `Y` to reload templates from disk on each request |

### OAuth Client Registration

Legacy single-client variables:

| Variable | Required | Description |
| --- | --- | --- |
| `NESTOR_CLIENT_ID` | Yes (unless using multi-client mode) | OAuth client ID accepted by Nestor |
| `NESTOR_REDIRECT_URIS` | Yes | Comma-separated list of allowed redirect URIs |
| `NESTOR_DEFAULT_RESOURCE_INDICATOR` | No | Audience used for access token issuance |

Multi-client mode variables:

| Variable | Required | Description |
| --- | --- | --- |
| `NESTOR_CLIENT_IDS` | Yes (for multi-client mode) | Comma-separated client IDs |
| `NESTOR_REDIRECT_URIS_<index>` | Yes | Redirect URIs for a client at index `0..n` |
| `NESTOR_DEFAULT_RESOURCE_INDICATOR_<index>` | No | Default resource indicator per client |

Example:

- `NESTOR_CLIENT_IDS=app-a,app-b`
- `NESTOR_REDIRECT_URIS_0=http://localhost:3000/callback`
- `NESTOR_REDIRECT_URIS_1=http://localhost:4000/callback`

### Connectors

Google is enabled when both variables are set:

- `NESTOR_CONNECTOR_GOOGLE_CLIENT_ID`
- `NESTOR_CONNECTOR_GOOGLE_CLIENT_SECRET`

Microsoft is enabled when all variables are set:

- `NESTOR_CONNECTOR_MICROSOFT_ISSUER`
- `NESTOR_CONNECTOR_MICROSOFT_CLIENT_ID`
- `NESTOR_CONNECTOR_MICROSOFT_CLIENT_SECRET`

### Couchbase (Optional)

Set `COUCHBASE_CONNECTION_STRING` to enable Couchbase storage.

| Variable | Required | Description |
| --- | --- | --- |
| `COUCHBASE_CONNECTION_STRING` | Yes (for Couchbase mode) | Couchbase connection string |
| `COUCHBASE_USERNAME` | Yes | Couchbase username |
| `COUCHBASE_PASSWORD` | Yes | Couchbase password |
| `COUCHBASE_BUCKET` | No | Bucket name. Default: `nestor` |
| `COUCHBASE_SCOPE` | No | Scope name. Default: `nestor` |

## Notes and Current Limitations

- The discovery document includes a `userinfo_endpoint`, but no `/userinfo` handler is currently exposed.
- Local account self-service flows (registration, password reset, profile management) are not currently exposed as HTTP endpoints.
- In-memory mode is for development only; data is lost on restart.

## Roadmap

- Passwordless login.
- User roles and permissions improvements.
- Additional OIDC connectors.
- Additional datastores.

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
