# OpenID Federation Proxy/Trust Anchor

This component acts as both an OpenID Federation Trust Anchor and an OpenID Connect Provider proxy. It bridges traditional OIDC providers with OpenID Federation by wrapping upstream OIDC providers and making them available through federation.

## Features

### ✅ Implemented Features

- **OpenID Federation Trust Anchor**: Acts as a trust anchor for federation entities
- **OIDC Provider Proxy**: Proxies authentication to upstream OIDC providers (Keycloak)
- **Federation Entity Statement**: Provides `.well-known/openid-federation` endpoint
- **Subordinate Management**: Manages subordinate entities (RPs) in the federation
- **Federation Endpoints**:
  - `/list` - Lists subordinate entities with proper iss/sub relationships
  - `/resolve` - Resolves entity statements with trust anchor signatures
  - `/fetch` - Fetches entity statements for validation
- **Dynamic Client Registration**: Supports federation-based client registration
- **OIDC Proxy Endpoints**:
  - `/authorize` - Proxies authorization with state/nonce/PKCE mapping
  - `/token` - Proxies token exchange
  - `/userinfo` - Proxies userinfo requests
  - `/jwks` - Provides federation JWKS
- **Multi-Trust Anchor Support**: Can participate in multiple trust chains
- **Proper Trust Chain Validation**: Issues subordinate statements with correct iss/sub

### 🔧 Configuration

The component is configured via `config.json`:

```json
{
  "entity_id": "https://your-op.example.com",
  "entity_name": "Your OpenID Provider",
  "trust_anchors": [
    "https://your-trust-anchor.example.com"
  ],
    "subordinates": [
    "https://your-op.example.com",
    "https://your-rp.example.com"
  ],
  "upstream_oidc_provider": "https://your-upstream-idp.example.com",
  "upstream_client_id": "your-upstream-client-id",
  "upstream_client_secret": "your-upstream-client-secret"
}
```

