# OpenID Federation OP Component

This directory contains a reference implementation of an OpenID Provider (OP) for OpenID Connect Federation.

- Dynamic client registration
- Federation entity statement endpoints
- OIDC proxy endpoints (authorize, token, userinfo)
- JWT-based trust and metadata
- Configurable trust anchors and upstream OIDC provider

## Getting Started
1. Copy `config.json.example` to `config.json` and fill in your deployment-specific values.
2. Build and run the OP:
   ```bash
   go build -o op op.go
   ./op
1. Copy `config.json.example` to `config.json` and fill in your deployment-specific values.
2. Build and run the OP:
   ```bash
   go build -o proxy proxy.go
   ./proxy
   ```
3. The OP will listen on port 8083 by default.
## Endpoints
- `/.well-known/openid-federation` — Entity statement
- `/jwks` — JWKS endpoint
- `/register` — Dynamic client registration
- `/authorize`, `/token`, `/userinfo` — OIDC proxy endpoints
- `/health` — Health check

## Development
- See `TODO.md` for planned improvements and security tasks.
- Contributions and suggestions welcome!

## License
MIT
