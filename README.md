# OpenID Federation Trust Anchor & OIDC Provider Proxy

This component serves as both an **OpenID Federation Trust Anchor** and an **OpenID Connect Provider proxy**. It bridges traditional OIDC providers with OpenID Federation by wrapping upstream OIDC providers and making them available through federation protocols.

## Overview

The Trust Anchor acts as a central authority in the federation, managing trust relationships and issuing signed entity statements. The OIDC proxy functionality allows legacy OIDC providers to participate in federation ecosystems without native federation support.

## Features

### ✅ Implemented Features

- **OpenID Federation Trust Anchor**: Acts as a trust anchor for federation entities
- **Federation Resolver Integration**: Uses external federation resolvers for entity discovery when configured
- **OIDC Provider Proxy**: Proxies authentication to upstream OIDC providers (Keycloak, etc.)
- **Federation Entity Statement**: Provides `.well-known/openid-federation` endpoint
- **Subordinate Management**: Manages subordinate entities (RPs) in the federation
- **Dynamic Client Registration**: Supports federation-based client registration with JWT validation
- **Multi-Trust Anchor Support**: Can participate in multiple trust chains
- **Proper Trust Chain Validation**: Issues subordinate statements with correct iss/sub relationships
- **Prometheus Metrics**: Exposes comprehensive metrics for monitoring and observability

### 🔗 Federation Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-federation` | GET | Self-issued entity statement |
| `/resolve?sub={entity_id}` | GET | Resolves entity statements (direct subordinates or via resolver) |
| `/list` | GET | Lists subordinate entities with trust anchor signatures |
| `/fetch` | GET | Fetches entity statements for validation |
| `/register` | POST | Federation-based dynamic client registration |
| `/jwks` | GET | Federation JWKS endpoint |
| `/health` | GET | Health check endpoint |
| `/metrics` | GET | Prometheus metrics endpoint |

### 🔄 OIDC Proxy Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET | Proxies authorization with state/nonce/PKCE mapping |
| `/token` | POST | Proxies token exchange with claim adjustment |
| `/userinfo` | GET | Proxies userinfo requests |
| `/callback` | GET | Handles upstream provider callbacks |

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Port to listen on | `8080` | No |
| `FEDERATION_RESOLVER_URL` | URL of federation resolver service | - | No |
| `ENTITY_ID` | The federation entity ID (typically the base URL) | `https://test-op.homelab.kodden.nl` | No |
| `ENTITY_NAME` | Human-readable name for the entity | `Test OpenID Provider` | No |
| `TRUST_ANCHORS` | Comma-separated list of trust anchor URLs | `https://test-op.homelab.kodden.nl,https://edugain.pilot1.sram.surf.nl,https://trust-anchor.pilot1.sram.surf.nl` | No |
| `UPSTREAM_OIDC_PROVIDER` | URL of the upstream OIDC provider to proxy | `https://connect.test.surfconext.nl` | No |
| `UPSTREAM_CLIENT_ID` | Client ID for upstream provider authentication | `test-op.homelab.kodden.nl` | No |
| `UPSTREAM_CLIENT_SECRET` | Client secret for upstream provider authentication | `1tx9EomiY4WsMfhSIWJl` | No |
| `SUBORDINATES` | Comma-separated list of subordinate entity IDs | `https://test-op.homelab.kodden.nl,https://test-rp.homelab.kodden.nl` | No |

## Federation Resolver Integration

When `FEDERATION_RESOLVER_URL` is configured, the trust anchor will use the resolver service for entity resolution:

### Resolution Logic

1. **Self-resolution**: Returns self-issued entity statement
2. **Direct subordinates**: Fetches and re-signs subordinate statements directly
3. **Resolver delegation**: For non-subordinate entities, delegates to the configured resolver
4. **Fallback**: Returns 404 if resolver fails or isn't configured

### Resolver API Usage

The component calls the resolver using:
```
GET {FEDERATION_RESOLVER_URL}/api/v1/resolve/{entity_id}[/trust-anchor/{trust_anchor}]
```

## Monitoring & Metrics

The component exposes comprehensive Prometheus metrics for monitoring federation operations and OIDC proxy performance.

### Available Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|---------|
| `http_requests_total` | Counter | Total number of HTTP requests | `method`, `endpoint`, `status` |
| `http_request_duration_seconds` | Histogram | HTTP request duration in seconds | `method`, `endpoint` |
| `registered_clients_total` | Gauge | Total number of registered clients | - |

### Metrics Endpoint

```bash
# Access metrics
curl http://localhost:8080/metrics
```

### Example Metrics Output

```
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",endpoint="/health",status="200"} 42
http_requests_total{method="POST",endpoint="/register",status="201"} 5

# HELP http_request_duration_seconds HTTP request duration in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",endpoint="/resolve",le="0.005"} 1
http_request_duration_seconds_bucket{method="GET",endpoint="/resolve",le="0.01"} 3

# HELP registered_clients_total Total number of registered clients
# TYPE registered_clients_total gauge
registered_clients_total 3
```

### Prometheus Configuration

Add the following scrape target to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'test-op'
    static_configs:
      - targets: ['test-op:8080']
    metrics_path: '/metrics'
```

## Docker Deployment

### Build and Run

```bash
# Build the container
docker build -t oidc-fed-op .

# Run with environment variables
docker run -p 8080:8080 \
  -e PORT=8080 \
  -e FEDERATION_RESOLVER_URL=http://resolver:8080 \
  -e ENTITY_ID=https://your-op.example.com \
  -e ENTITY_NAME="Your OpenID Provider" \
  -e TRUST_ANCHORS=https://your-trust-anchor.example.com \
  -e UPSTREAM_OIDC_PROVIDER=https://provider.example.com \
  -e UPSTREAM_CLIENT_ID=your-client-id \
  -e UPSTREAM_CLIENT_SECRET=your-client-secret \
  -e SUBORDINATES=https://your-op.example.com,https://your-rp.example.com \
  oidc-fed-op
```

### Docker Compose Integration

```yaml
test-op:
  build:
    context: ./op
    dockerfile: Dockerfile
  ports:
    - "8080:8080"
  environment:
    - PORT=8080
    - FEDERATION_RESOLVER_URL=http://resolver:8080
    - ENTITY_ID=https://your-op.example.com
    - ENTITY_NAME=Your OpenID Provider
    - TRUST_ANCHORS=https://your-trust-anchor.example.com
    - UPSTREAM_OIDC_PROVIDER=https://provider.example.com
    - UPSTREAM_CLIENT_ID=your-client-id
    - UPSTREAM_CLIENT_SECRET=your-client-secret
    - SUBORDINATES=https://your-op.example.com,https://your-rp.example.com
  depends_on:
    - resolver
```

## API Usage Examples

### Resolve Entity

```bash
# Resolve a direct subordinate
curl "http://localhost:8080/resolve?sub=https://test-rp.example.com"

# Resolve via resolver (if configured)
curl "http://localhost:8080/resolve?sub=https://external-entity.example.com"
```

### List Subordinates

```bash
curl "http://localhost:8080/list"
```

### Client Registration

```bash
curl -X POST "http://localhost:8080/register" \
  -H "Content-Type: application/entity-statement+jwt" \
  -d "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoicnAta2V5LTEi..."
```

## Architecture

### Trust Chain Flow

```
[External RP] → [Trust Anchor /resolve] → [Resolver] → [Target Entity]
                                      ↓
                               [Direct Subordinates]
```

### Authentication Flow

```
[RP] → [Trust Anchor /authorize] → [Upstream OIDC /authorize] → [User Auth]
    ← [Trust Anchor /callback] ← [Upstream OIDC /callback] ← [User]
    → [Trust Anchor /token] → [Upstream OIDC /token] → [Token Response]
```

## Security Considerations

- **JWT Validation**: All federation JWTs are cryptographically validated
- **Trust Anchor Authority**: Only issues statements for configured subordinates
- **Resolver Security**: Validates resolver responses before forwarding
- **Client Registration**: Requires valid federation entity statements
- **Token Proxying**: Maintains security context across proxy boundaries

## Development

### Building

```bash
cd op
go build -o test-op .
```

### Testing

```bash
# Health check
curl http://localhost:8080/health

# Federation discovery
curl http://localhost:8080/.well-known/openid-federation

# Metrics endpoint
curl http://localhost:8080/metrics
```

### Debugging

Enable debug logging by setting log level in the application code. The component provides detailed logs for:
- Federation resolution attempts
- Resolver interactions
- Client registration validation
- Authentication proxying

## Troubleshooting

### Common Issues

1. **Resolver Connection Failed**
   - Check `FEDERATION_RESOLVER_URL` configuration
   - Verify resolver service is running and accessible
   - Check network connectivity between containers

2. **Entity Not Found**
   - Verify entity is either a direct subordinate or discoverable via resolver
   - Check trust anchor configuration
   - Validate entity ID format

3. **Client Registration Failed**
   - Ensure registration JWT is properly signed
   - Verify `aud` claim matches trust anchor entity ID
   - Check `authority_hints` include configured trust anchors

4. **Metrics Not Available**
   - Ensure `/metrics` endpoint is accessible
   - Check Prometheus scrape configuration
   - Verify metrics are being collected (check logs for errors)

### Health Checks

The component provides a `/health` endpoint that returns:
- Service status and configuration
- Registered client count
- Trust anchor and subordinate information
- Timestamp for monitoring

The `/metrics` endpoint provides detailed Prometheus metrics for monitoring federation operations and performance.

## License

This component is part of the OpenID Federation VRE consolidated project.

