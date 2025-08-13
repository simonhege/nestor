# Nestor

Nestor is a simple account manager for web applications.
It allows your user to connect either via local account or using a 3rd party Open ID Connect service,
such as Google or Azure.

Nestor can be deployed as a serverless application.

## Features

### Authorization Code Grant with Proof Key for Code Exchange (PKCE)
TODO move this and add more details in another page

1. Nestor receives request and code_challenge from the client.
2. Nestor displays a login page with a button to connect to the OIDC provider.
3. Nestor redirects the user to the OIDC provider for authentication.
4. The OIDC provider authenticates the user and redirects back to Nestor with a code.
5. Nestor exchanges the code for an access token and ID token.
6. Nestor verifies the ID token and retrieves user information.
7. Nestor creates a local account or updates an existing one with the user information.
8. Nestor replies to the client with an authorization code.
9. The client exchanges the authorization code and code verifier for an access token and ID token.
10. The client can now access protected resources using the access token.

### Local Accounts
Nestor supports local accounts with the following features:
- Registration with email and password.
- Login with email and password.
- Password reset functionality.
- User profile management.


## Configuration

### OIDC providers
Supported OIDC providers are:
- Google
- Azure AD

### Datastores
Nestor requires a datastore for local accounts and for some session management operations.

Supported datastores are:
- In memory (for local development only)
- Couchbase



## Local development
```bash
go install
```

Create a `.env` file in the root directory with the following content:
```env
BASE_URL=http://localhost:9021
PORT=9021
ISSUER=http://localhost:9021/
DEBUG_TEMPLATES=Y
```

Then run the application with:
```bash
nestor
```

## Deployment
TODO: detail how to deploy

## TODO
- [ ] Add support for refresh tokens.
- [ ] Passwordless login.
- [ ] Add support for user roles and permissions.
- [ ] Add support for more OIDC flows (e.g., Implicit Flow, Client Credentials Flow).
- [ ] Add support for more OIDC providers (e.g., GitHub, Facebook).
- [ ] Add support for more datastores (e.g., MongoDB).
