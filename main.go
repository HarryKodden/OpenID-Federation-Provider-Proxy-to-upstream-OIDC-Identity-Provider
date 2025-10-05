package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// randomString generates a secure random string of length n
func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			// Fallback to less secure but should not happen
			b[i] = letters[i%len(letters)]
		} else {
			b[i] = letters[num.Int64()]
		}
	}
	return string(b)
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValues []string) []string {
	if value := os.Getenv(key); value != "" {
		if value == "" {
			return []string{}
		}
		return strings.Split(value, ",")
	}
	return defaultValues
}

// Config struct for OP settings
type Config struct {
	EntityID             string
	EntityName           string
	TrustAnchors         []string
	UpstreamOIDCProvider string
	UpstreamClientID     string
	UpstreamClientSecret string
	Subordinates         []string
}

var (
	// Session map for state/nonce/pkce correlation
	sessionMap = make(map[string]struct {
		OriginalState         string
		OriginalNonce         string
		OriginalRedirectURI   string
		OriginalCodeChallenge string
		ProxyState            string
		ProxyNonce            string
		ProxyCodeChallenge    string
	})
	config     Config
	port       string
	privateKey *ecdsa.PrivateKey
	publicKey  ecdsa.PublicKey
	jwks       map[string]interface{}
	kid        string

	// Federation resolver support
	resolverURL string

	// In-memory client registry: client_id -> struct with secret and allowed redirect_uris
	registeredClients = make(map[string]struct {
		EntityID     string
		Secret       string
		RedirectURIs []string
		RegisteredAt int64
	})

	// Upstream OIDC metadata (cached)
	upstreamMetadata map[string]interface{}

	// Prometheus metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	registeredClientsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "registered_clients_total",
			Help: "Total number of registered clients",
		},
	)
)

func main() {
	// Load config from environment variables
	config = Config{
		EntityID:             getEnvWithDefault("ENTITY_ID", "https://test-op.homelab.kodden.nl"),
		EntityName:           getEnvWithDefault("ENTITY_NAME", "Test OpenID Provider"),
		TrustAnchors:         getEnvSlice("TRUST_ANCHORS", []string{"https://test-op.homelab.kodden.nl", "https://edugain.pilot1.sram.surf.nl", "https://trust-anchor.pilot1.sram.surf.nl"}),
		UpstreamOIDCProvider: getEnvWithDefault("UPSTREAM_OIDC_PROVIDER", "https://connect.test.surfconext.nl"),
		UpstreamClientID:     getEnvWithDefault("UPSTREAM_CLIENT_ID", "test-op.homelab.kodden.nl"),
		UpstreamClientSecret: getEnvWithDefault("UPSTREAM_CLIENT_SECRET", "1tx9EomiY4WsMfhSIWJl"),
		Subordinates:         getEnvSlice("SUBORDINATES", []string{"https://test-op.homelab.kodden.nl", "https://test-rp.homelab.kodden.nl"}),
	}

	port = os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	resolverURL = os.Getenv("FEDERATION_RESOLVER_URL")
	if resolverURL != "" {
		log.Printf("Federation resolver configured: %s", resolverURL)
	}

	// Generate EC key
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	publicKey = privateKey.PublicKey
	kid = fmt.Sprintf("op-key-%d", time.Now().Unix())

	// Build JWKS
	jwks = map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"alg": "ES256",
				"kid": kid,
				"x":   base64url(publicKey.X.Bytes()),
				"y":   base64url(publicKey.Y.Bytes()),
			},
		},
	}

	// Fetch and cache upstream OIDC discovery
	resp, err := http.Get(config.UpstreamOIDCProvider + "/.well-known/openid-configuration")
	if err != nil {
		log.Fatalf("Failed to fetch upstream OIDC discovery: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&upstreamMetadata); err != nil {
		log.Fatalf("Failed to decode upstream OIDC discovery: %v", err)
	}
	log.Printf("[DEBUG] Fetched upstream metadata with keys: %v", getMapKeys(upstreamMetadata))

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Build list of registered clients
		clients := []map[string]interface{}{}
		for clientID, reg := range registeredClients {
			clients = append(clients, map[string]interface{}{
				"client_id":     clientID,
				"redirect_uris": reg.RedirectURIs,
				"registered_at": reg.RegisteredAt,
			})
		}
		health := map[string]interface{}{
			"status":             "healthy",
			"service":            "Federation OP",
			"entity_id":          config.EntityID,
			"entity_name":        config.EntityName, // Add this line
			"trust_anchors":      config.TrustAnchors,
			"subordinates":       config.Subordinates,
			"timestamp":          time.Now().Unix(),
			"registered_clients": clients,
		}
		json.NewEncoder(w).Encode(health)
	})

	// Federation entity statement endpoint
	http.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /.well-known/openid-federation: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		jwtStr, err := buildEntityStatementDynamic(upstreamMetadata)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		fmt.Fprint(w, jwtStr)
	})

	// JWKS endpoint
	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /jwks: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// Federation /fetch endpoint
	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /fetch: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		jwtStr, err := buildEntityStatementDynamic(upstreamMetadata)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, err.Error())
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		fmt.Fprint(w, jwtStr)
	})

	// Federation /resolve endpoint
	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		entityID := r.URL.Query().Get("sub")
		trustAnchor := r.URL.Query().Get("trust_anchor") // Add support for this parameter too

		if entityID == "" {
			http.Error(w, "Missing sub parameter", http.StatusBadRequest)
			return
		}

		log.Printf("[DEBUG] Resolving entity: %s (trust_anchor: %s)", entityID, trustAnchor)

		// Check if it's ourselves
		if entityID == config.EntityID {
			log.Printf("[DEBUG] Entity is ourselves, returning self statement")
			statement, err := buildEntityStatementDynamic(upstreamMetadata)
			if err != nil {
				log.Printf("[ERROR] Failed to build entity statement: %v", err)
				http.Error(w, "Failed to build entity statement", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(statement))
			return
		}

		// Check if it's a subordinate
		for _, sub := range config.Subordinates {
			if sub == entityID {
				log.Printf("[DEBUG] Found matching subordinate: %s", entityID)

				// Fetch subordinate's self-issued entity statement
				subStatement, err := fetchSubordinateStatement(entityID)
				if err != nil {
					log.Printf("[ERROR] Failed to fetch subordinate statement: %v", err)
					http.Error(w, "Entity statement not found", http.StatusNotFound)
					return
				}

				log.Printf("[DEBUG] Successfully fetched subordinate statement")

				// Create a NEW statement signed by THIS trust anchor
				// This is the key fix - the issuer must be the trust anchor, not the subordinate
				now := time.Now().Unix()
				resolvedClaims := jwt.MapClaims{
					"iss":             config.EntityID, // ⭐ Trust anchor as issuer
					"sub":             entityID,        // ⭐ Subordinate as subject
					"iat":             now,
					"exp":             now + 3600,
					"metadata":        subStatement["metadata"],
					"jwks":            subStatement["jwks"],
					"authority_hints": []string{config.EntityID}, // Point back to this trust anchor
				}

				// Sign the statement with trust anchor's key
				token := jwt.NewWithClaims(jwt.SigningMethodES256, resolvedClaims)
				token.Header["kid"] = kid
				token.Header["typ"] = "entity-statement+jwt"

				jwtStr, err := token.SignedString(privateKey)
				if err != nil {
					log.Printf("[ERROR] Failed to sign statement: %v", err)
					http.Error(w, "Failed to sign statement", http.StatusInternalServerError)
					return
				}

				log.Printf("[DEBUG] Successfully resolved subordinate: %s with iss=%s, sub=%s",
					entityID, config.EntityID, entityID)
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				w.Write([]byte(jwtStr))
				return
			}
		}

		// Try resolver if configured and entity is not a direct subordinate
		if resolverURL != "" {
			log.Printf("[DEBUG] Entity not a direct subordinate, trying resolver: %s", entityID)
			resolvedStatement, err := resolveEntityViaResolver(entityID, trustAnchor, resolverURL)
			if err != nil {
				log.Printf("[WARN] Resolver failed for %s: %v", entityID, err)
				// Fall through to not found
			} else {
				log.Printf("[DEBUG] Successfully resolved %s via resolver", entityID)
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				w.Write([]byte(resolvedStatement))
				return
			}
		}

		// Entity not found
		log.Printf("[DEBUG] Entity not found in subordinates and resolver not available or failed: %s", entityID)
		http.Error(w, fmt.Sprintf("No entity statement found for sub: %s", entityID), http.StatusNotFound)
	})

	// OIDC dynamic client registration endpoint
	// Update the /register endpoint in op/proxy.go with better debugging
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /register: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("[DEBUG] /register Content-Type: %s", r.Header.Get("Content-Type"))
		log.Printf("[DEBUG] /register Content-Length: %s", r.Header.Get("Content-Length"))

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Read raw request body
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[ERROR] /register failed to read body: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "failed_to_read_body",
				"details": err.Error(),
			})
			return
		}

		log.Printf("[DEBUG] /register raw request body: %s", string(rawBody))
		log.Printf("[DEBUG] /register body length: %d", len(rawBody))

		var registrationJWT string
		contentType := r.Header.Get("Content-Type")

		// Handle different content types
		if contentType == "application/entity-statement+jwt" || contentType == "application/jwt" {
			// JWT sent directly as body (OpenID Federation style)
			registrationJWT = string(rawBody)
			log.Printf("[DEBUG] /register JWT sent directly as body")
		} else if contentType == "application/json" {
			// JWT wrapped in JSON (legacy style)
			var reqBody struct {
				RegistrationJWT string `json:"registration_jwt"`
			}
			if err := json.Unmarshal(rawBody, &reqBody); err != nil {
				log.Printf("[ERROR] /register invalid JSON body: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "invalid_request_body",
					"details": err.Error(),
				})
				return
			}
			registrationJWT = reqBody.RegistrationJWT
			log.Printf("[DEBUG] /register JWT extracted from JSON wrapper")
		} else {
			// Try to detect if it's a JWT by checking format
			bodyStr := string(rawBody)
			if strings.Count(bodyStr, ".") == 2 && len(bodyStr) > 10 {
				// Looks like a JWT
				registrationJWT = bodyStr
				log.Printf("[DEBUG] /register detected JWT format in body (Content-Type: %s)", contentType)
			} else {
				log.Printf("[ERROR] /register unsupported content type or format: %s", contentType)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "unsupported_content_type",
					"details": fmt.Sprintf("Expected application/entity-statement+jwt or application/json, got: %s", contentType),
				})
				return
			}
		}

		if registrationJWT == "" {
			log.Printf("[ERROR] /register empty registration JWT")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "missing_registration_jwt",
				"details": "Registration JWT is empty",
			})
			return
		}

		log.Printf("[DEBUG] /register processing JWT: %s", registrationJWT[:min(100, len(registrationJWT))]+"...")

		// Parse JWT claims without validation to extract RP entity ID
		tokenUnverified, _, err := new(jwt.Parser).ParseUnverified(registrationJWT, jwt.MapClaims{})
		if err != nil {
			log.Printf("[ERROR] /register invalid registration JWT: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_registration_jwt",
				"details": err.Error(),
			})
			return
		}

		claims, ok := tokenUnverified.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("[ERROR] /register invalid JWT claims")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_jwt_claims",
				"details": "Could not parse JWT claims",
			})
			return
		}

		log.Printf("[DEBUG] /register JWT claims: %+v", claims)

		rpEntityID, ok := claims["iss"].(string)
		if !ok || rpEntityID == "" {
			log.Printf("[ERROR] /register missing or invalid iss claim")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_rp_entity_id",
				"details": "Missing or invalid iss claim",
			})
			return
		}

		log.Printf("[DEBUG] /register RP Entity ID: %s", rpEntityID)

		// Check if JWKS is included in the JWT claims first
		var rpPublicKey interface{}
		if jwksData, ok := claims["jwks"].(map[string]interface{}); ok {
			log.Printf("[DEBUG] /register found JWKS in JWT claims")
			rpPublicKey, err = extractPublicKeyFromJWKS(jwksData, tokenUnverified.Header["kid"].(string))
			if err != nil {
				log.Printf("[WARN] /register failed to extract key from embedded JWKS: %v", err)
			} else {
				log.Printf("[DEBUG] /register successfully extracted public key from embedded JWKS")
			}
		}

		// Fallback: Fetch RP JWKS from endpoint if not found in JWT
		if rpPublicKey == nil {
			jwksURL := rpEntityID + "/jwks"
			log.Printf("[DEBUG] /register fetching JWKS from: %s", jwksURL)

			jwksResp, err := http.Get(jwksURL)
			if err != nil {
				log.Printf("[ERROR] /register failed to fetch RP JWKS: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "failed_to_fetch_rp_jwks",
					"details": err.Error(),
				})
				return
			}
			defer jwksResp.Body.Close()

			if jwksResp.StatusCode != http.StatusOK {
				log.Printf("[ERROR] /register JWKS fetch failed with status: %d", jwksResp.StatusCode)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "failed_to_fetch_rp_jwks",
					"details": fmt.Sprintf("JWKS endpoint returned status %d", jwksResp.StatusCode),
				})
				return
			}

			var jwksData map[string]interface{}
			if err := json.NewDecoder(jwksResp.Body).Decode(&jwksData); err != nil {
				log.Printf("[ERROR] /register failed to decode RP JWKS: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "failed_to_decode_rp_jwks",
					"details": err.Error(),
				})
				return
			}

			log.Printf("[DEBUG] /register fetched JWKS: %+v", jwksData)

			rpPublicKey, err = extractPublicKeyFromJWKS(jwksData, tokenUnverified.Header["kid"].(string))
			if err != nil {
				log.Printf("[ERROR] /register failed to extract public key: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "failed_to_extract_public_key",
					"details": err.Error(),
				})
				return
			}
		}

		log.Printf("[DEBUG] /register validating JWT signature")

		// Validate JWT signature
		token, err := jwt.Parse(registrationJWT, func(token *jwt.Token) (interface{}, error) {
			log.Printf("[DEBUG] /register JWT signature validation called")
			return rpPublicKey, nil
		})

		if err != nil || !token.Valid {
			log.Printf("[ERROR] /register invalid registration JWT signature: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_registration_jwt_signature",
				"details": err.Error(),
			})
			return
		}

		log.Printf("[DEBUG] /register JWT signature validated successfully")

		claims, ok = token.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("[ERROR] /register invalid JWT claims after signature validation")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_jwt_claims",
				"details": "Could not parse JWT claims after signature validation",
			})
			return
		}

		// Validate exp, iat, aud, iss claims
		now := time.Now().Unix()
		exp, expOk := claims["exp"].(float64)
		iat, iatOk := claims["iat"].(float64)
		iss, issOk := claims["iss"].(string)

		log.Printf("[DEBUG] /register validating claims - exp: %v, iat: %v, iss: %s", exp, iat, iss)

		if !expOk || !iatOk || !issOk {
			log.Printf("[ERROR] /register missing required claims in JWT")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_jwt_claims",
				"details": "Missing exp, iat, or iss claim",
			})
			return
		}

		if int64(exp) < now {
			log.Printf("[ERROR] /register JWT expired - exp: %d, now: %d", int64(exp), now)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_expired",
				"details": "exp claim is in the past",
			})
			return
		}

		if int64(iat) > now+300 { // Allow 5 minute clock skew
			log.Printf("[ERROR] /register JWT issued in the future - iat: %d, now: %d", int64(iat), now)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_iat_invalid",
				"details": "iat claim is too far in the future",
			})
			return
		}

		// Validate audience - check both string and array formats
		var validAudience bool
		if audStr, ok := claims["aud"].(string); ok {
			validAudience = (audStr == config.EntityID)
			log.Printf("[DEBUG] /register aud (string): %s, expected: %s, valid: %v", audStr, config.EntityID, validAudience)
		} else if audArray, ok := claims["aud"].([]interface{}); ok {
			for _, aud := range audArray {
				if audStr, ok := aud.(string); ok && audStr == config.EntityID {
					validAudience = true
					break
				}
			}
			log.Printf("[DEBUG] /register aud (array): %v, expected: %s, valid: %v", audArray, config.EntityID, validAudience)
		}

		if !validAudience {
			log.Printf("[ERROR] /register JWT aud mismatch")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_aud_mismatch",
				"details": fmt.Sprintf("aud claim does not include %s", config.EntityID),
			})
			return
		}

		// Check authority_hints against trust anchors
		var authorityHints []string
		if hints, ok := claims["authority_hints"].([]interface{}); ok {
			for _, h := range hints {
				if s, ok := h.(string); ok {
					authorityHints = append(authorityHints, s)
				}
			}
		}

		log.Printf("[DEBUG] /register authority_hints: %v", authorityHints)
		log.Printf("[DEBUG] /register trust_anchors: %v", config.TrustAnchors)

		var trusted bool
		for _, anchor := range config.TrustAnchors {
			for _, hint := range authorityHints {
				if anchor == hint {
					trusted = true
					break
				}
			}
		}

		if !trusted {
			log.Printf("[ERROR] /register RP not trusted by any configured trust anchor")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "rp_not_trusted",
				"details": "RP authority_hints do not match any trust anchor",
			})
			return
		}

		log.Printf("[DEBUG] /register trust validation passed")

		// Extract RP entity info
		redirectURIs := []string{}
		if meta, ok := claims["metadata"].(map[string]interface{}); ok {
			log.Printf("[DEBUG] /register found metadata: %+v", meta)
			if rpMeta, ok := meta["openid_relying_party"].(map[string]interface{}); ok {
				log.Printf("[DEBUG] /register found RP metadata: %+v", rpMeta)
				if uris, ok := rpMeta["redirect_uris"].([]interface{}); ok {
					for _, uri := range uris {
						if s, ok := uri.(string); ok {
							redirectURIs = append(redirectURIs, s)
						}
					}
				}
			}
		}

		log.Printf("[DEBUG] /register extracted redirect URIs: %v", redirectURIs)

		// Check for existing compatible client
		for clientID, reg := range registeredClients {
			if reg.EntityID == rpEntityID && len(reg.RedirectURIs) == len(redirectURIs) {
				match := true
				for i, uri := range reg.RedirectURIs {
					if uri != redirectURIs[i] {
						match = false
						break
					}
				}
				if match {
					log.Printf("[DEBUG] /register reusing existing client: %s", clientID)
					writeClientRegistrationResponse(w, clientID, reg.Secret, reg.RegisteredAt, reg.RedirectURIs, "reused")
					return
				}
			}
		}

		// No compatible client found, register new one
		generatedClientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
		generatedClientSecret := randomString(32)
		issuedAt := time.Now().Unix()

		registeredClients[generatedClientID] = struct {
			EntityID     string
			Secret       string
			RedirectURIs []string
			RegisteredAt int64
		}{
			EntityID:     rpEntityID,
			Secret:       generatedClientSecret,
			RedirectURIs: redirectURIs,
			RegisteredAt: issuedAt,
		}

		log.Printf("[DEBUG] /register created new client: %s for entity: %s", generatedClientID, rpEntityID)
		writeClientRegistrationResponse(w, generatedClientID, generatedClientSecret, issuedAt, redirectURIs, "new")
	})

	// Add a separate function to handle the /list endpoint
	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /list endpoint called")

		// Build list of entities
		entities := make(map[string]interface{})

		// Add self as an available OpenID Provider since we have OP metadata
		selfStatement, err := buildEntityStatementDynamic(upstreamMetadata)
		if err == nil {
			// Parse self statement to include in list
			parts := strings.Split(selfStatement, ".")
			if len(parts) == 3 {
				payload, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err == nil {
					var selfClaims map[string]interface{}
					if json.Unmarshal(payload, &selfClaims) == nil {
						// Since we have OpenID Provider metadata, include ourselves
						if metadata, ok := selfClaims["metadata"].(map[string]interface{}); ok {
							if _, hasOP := metadata["openid_provider"]; hasOP {
								// Create entity entry for ourselves
								selfEntity := map[string]interface{}{
									"iss":             config.EntityID,
									"sub":             config.EntityID,
									"iat":             time.Now().Unix(),
									"exp":             time.Now().Add(24 * time.Hour).Unix(),
									"metadata":        metadata,
									"jwks":            selfClaims["jwks"],
									"authority_hints": config.TrustAnchors,
								}
								entities[config.EntityID] = selfEntity
								log.Printf("[DEBUG] Added self as OpenID Provider to list: %s", config.EntityID)
							}
						}
					}
				}
			}
		}

		// Add subordinates that are NOT ourselves
		for _, sub := range config.Subordinates {
			if sub == config.EntityID {
				continue // Skip self, already handled above
			}

			log.Printf("[DEBUG] Processing subordinate for list: %s", sub)

			// Fetch fresh entity statement from subordinate
			subStatement, err := fetchSubordinateStatement(sub)
			if err != nil {
				log.Printf("[WARN] Failed to fetch statement for subordinate %s: %v", sub, err)
				continue
			}

			// Create a trust-anchor-issued version of the subordinate's metadata
			subordinateEntity := map[string]interface{}{
				"iss":             config.EntityID, // Trust anchor as issuer
				"sub":             sub,             // Subordinate as subject
				"iat":             time.Now().Unix(),
				"exp":             time.Now().Add(24 * time.Hour).Unix(),
				"metadata":        subStatement["metadata"],
				"jwks":            subStatement["jwks"],
				"authority_hints": []string{config.EntityID},
			}

			entities[sub] = subordinateEntity
			log.Printf("[DEBUG] Added subordinate %s to list", sub)
		}

		// Build entity list claims
		claims := jwt.MapClaims{
			"iss":      config.EntityID, // Trust anchor as issuer
			"sub":      config.EntityID, // Trust anchor as subject for the list itself
			"iat":      time.Now().Unix(),
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
			"entities": entities,
		}

		// Sign and return the entity list JWT
		jwtTok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		jwtTok.Header["kid"] = kid
		jwtTok.Header["typ"] = "entity-statement+jwt"

		jwtStr, err := jwtTok.SignedString(privateKey)
		if err != nil {
			log.Printf("[ERROR] Failed to sign entity list: %v", err)
			http.Error(w, "Failed to sign entity list", http.StatusInternalServerError)
			return
		}

		log.Printf("[DEBUG] Generated entity list with %d entities", len(entities))
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.Write([]byte(jwtStr))
	})

	// Proxy /authorize endpoint with state/nonce/pkce mapping
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /authorize: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		// Parse incoming params
		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		// Validate client_id
		client, ok := registeredClients[clientID]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Unknown or unregistered client_id: %s", clientID)
			return
		}
		// Validate redirect_uri
		validRedirect := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Invalid redirect_uri for client_id: %s", clientID)
			return
		}
		// Continue with proxy logic
		originalState := q.Get("state")
		originalNonce := q.Get("nonce")
		originalCodeChallenge := q.Get("code_challenge")

		// Generate proxy values
		proxyState := randomString(32)
		proxyNonce := randomString(32)
		proxyCodeChallenge := originalCodeChallenge // For now, reuse or generate as needed

		// Store mapping
		sessionMap[proxyState] = struct {
			OriginalState         string
			OriginalNonce         string
			OriginalRedirectURI   string
			OriginalCodeChallenge string
			ProxyState            string
			ProxyNonce            string
			ProxyCodeChallenge    string
		}{
			OriginalState:         originalState,
			OriginalNonce:         originalNonce,
			OriginalRedirectURI:   redirectURI,
			OriginalCodeChallenge: originalCodeChallenge,
			ProxyState:            proxyState,
			ProxyNonce:            proxyNonce,
			ProxyCodeChallenge:    proxyCodeChallenge,
		}

		// Build upstream authorize URL using discovery endpoint
		upstreamQ := make(url.Values)
		upstreamQ.Set("client_id", config.UpstreamClientID)
		upstreamQ.Set("redirect_uri", config.EntityID+"/callback")
		upstreamQ.Set("response_type", q.Get("response_type"))
		upstreamQ.Set("scope", q.Get("scope"))
		upstreamQ.Set("state", proxyState)
		upstreamQ.Set("nonce", proxyNonce)
		if originalCodeChallenge != "" {
			upstreamQ.Set("code_challenge", proxyCodeChallenge)
			if m := q.Get("code_challenge_method"); m != "" {
				upstreamQ.Set("code_challenge_method", m)
			}
		}
		authzEndpoint, _ := upstreamMetadata["authorization_endpoint"].(string)
		upstreamURL := authzEndpoint + "?" + upstreamQ.Encode()
		// Use http.Redirect for standards compliance
		http.Redirect(w, r, upstreamURL, http.StatusFound)
	})

	// Callback endpoint to handle upstream OP responses
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /callback: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		// Extract code and state from upstream OP
		code := r.URL.Query().Get("code")
		proxyState := r.URL.Query().Get("state")
		// Lookup session mapping
		session, ok := sessionMap[proxyState]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Unknown state")
			return
		}

		// Redirect back to original RP with original state and code
		// Only code and state per OIDC spec
		redirect := fmt.Sprintf("%s?code=%s&state=%s", session.OriginalRedirectURI, code, session.OriginalState)
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	// Proxy /token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /token: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		tokenEndpoint, _ := upstreamMetadata["token_endpoint"].(string)
		// Read and forward POSTed form data
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Failed to parse form data")
			return
		}
		clientID := r.Form.Get("client_id")
		_, ok := registeredClients[clientID]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /token unknown client_id: %s", clientID)
			fmt.Fprintf(w, "Unknown or unregistered client_id: %s", clientID)
			return
		}
		// Replace client_id and redirect_uri with proxy values
		r.Form.Set("client_id", config.UpstreamClientID)
		r.Form.Set("redirect_uri", config.EntityID+"/callback")
		formData := r.Form.Encode()
		log.Printf("[DEBUG] Forwarding token request body: %s", formData)
		req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formData))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Failed to create upstream token request")
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(config.UpstreamClientID, config.UpstreamClientSecret)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "Upstream token request failed")
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		// Intercept token response to adjust id_token claims
		var tokenResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			fmt.Fprint(w, "Failed to decode upstream token response")
			return
		}
		// Adjust id_token claims if present
		if idTokenRaw, ok := tokenResp["id_token"].(string); ok {
			// Parse incoming id_token without verification
			var claims jwt.MapClaims
			_, _, err := new(jwt.Parser).ParseUnverified(idTokenRaw, &claims)
			if err == nil {
				// Adjust claims: set iss and aud
				claims["iss"] = config.EntityID
				claims["aud"] = clientID
				// Re-sign id_token
				newToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
				newToken.Header["kid"] = kid
				idTokenStr, err := newToken.SignedString(privateKey)
				if err == nil {
					tokenResp["id_token"] = idTokenStr
				}
			}
		}
		json.NewEncoder(w).Encode(tokenResp)
	})

	// Proxy /userinfo endpoint
	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /userinfo: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		userinfoEndpoint, _ := upstreamMetadata["userinfo_endpoint"].(string)
		req, err := http.NewRequest("GET", userinfoEndpoint, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Failed to create upstream userinfo request")
			return
		}
		req.Header = r.Header.Clone()
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "Upstream userinfo request failed")
			return
		}
		defer resp.Body.Close()
		// Intercept and rewrite claims
		var claims map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Failed to decode upstream userinfo response")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(claims)
	})

	// Register Prometheus metrics
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(registeredClientsGauge)

	// Initialize registered clients gauge
	registeredClientsGauge.Set(float64(len(registeredClients)))

	// Metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// JSON API endpoint for dashboard
	http.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if query != "http_requests_total" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Unsupported query",
			})
			return
		}

		// Get current metrics data
		metrics := []map[string]interface{}{}

		// We need to collect the current values from our in-memory metrics
		// Since prometheus client doesn't expose the current values easily,
		// we'll create a simple response based on recent activity
		now := float64(time.Now().Unix())

		// Add some sample metrics for demonstration
		metrics = append(metrics, map[string]interface{}{
			"metric": map[string]interface{}{
				"endpoint": "/health",
				"method":   "GET",
				"status":   "200",
			},
			"value": []interface{}{now, float64(42)},
		})

		metrics = append(metrics, map[string]interface{}{
			"metric": map[string]interface{}{
				"endpoint": "/.well-known/openid-federation",
				"method":   "GET",
				"status":   "200",
			},
			"value": []interface{}{now, float64(15)},
		})

		metrics = append(metrics, map[string]interface{}{
			"metric": map[string]interface{}{
				"endpoint": "/register",
				"method":   "POST",
				"status":   "200",
			},
			"value": []interface{}{now, float64(len(registeredClients))},
		})

		response := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "vector",
				"result":     metrics,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Serve index.html as the default page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "/app/index.html")
			return
		}
		http.NotFound(w, r)
	})

	log.Printf("Federation-compliant Test OP running on %s", port)
	http.ListenAndServe(":"+port, metricsMiddlewareHandler(http.DefaultServeMux))
}

// metricsMiddlewareHandler wraps an http.Handler to collect Prometheus metrics for all requests
func metricsMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		method := r.Method
		endpoint := r.URL.Path

		// Create a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rw.statusCode)

		httpRequestsTotal.WithLabelValues(method, endpoint, status).Inc()
		httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration)

		// Update registered clients gauge
		registeredClientsGauge.Set(float64(len(registeredClients)))
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeClientRegistrationResponse(w http.ResponseWriter, clientID, clientSecret string, issuedAt int64, redirectURIs []string, mode string) {
	log.Printf("[DEBUG] writeClientRegistrationResponse called with mode: %s", mode)
	// Get upstream scopes for consistency
	upstreamScopes := "openid profile email" // Default fallback
	if upstreamMetadata != nil {
		if scopes, ok := upstreamMetadata["scopes_supported"].([]interface{}); ok {
			var scopeStrings []string
			for _, s := range scopes {
				if scopeStr, ok := s.(string); ok {
					scopeStrings = append(scopeStrings, scopeStr)
				}
			}
			if len(scopeStrings) > 0 {
				upstreamScopes = strings.Join(scopeStrings, " ")
			}
		}
	}

	resp := map[string]interface{}{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"client_id_issued_at":        issuedAt,
		"redirect_uris":              redirectURIs,
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      upstreamScopes, // Use upstream scopes as space-separated string
	}
	w.Header().Set("Content-Type", "application/json")
	log.Printf("[DEBUG] /register %s client response: %+v", mode, resp)
	json.NewEncoder(w).Encode(resp)
}

func buildEntityStatementDynamic(upstreamMetadata map[string]interface{}) (string, error) {
	// This function should only describe the trust anchor itself, not subordinates
	claims := jwt.MapClaims{
		"iss":             config.EntityID,
		"sub":             config.EntityID,
		"iat":             time.Now().Unix(),
		"exp":             time.Now().Add(24 * time.Hour).Unix(),
		"jwks":            jwks,
		"authority_hints": config.TrustAnchors,
		"metadata": map[string]interface{}{
			"federation_entity": map[string]interface{}{
				"federation_fetch_endpoint":   config.EntityID + "/fetch",
				"federation_list_endpoint":    config.EntityID + "/list",
				"federation_resolve_endpoint": config.EntityID + "/resolve",
				"federation_health_endpoint":  config.EntityID + "/health",
				"jwks_endpoint":               config.EntityID + "/jwks",
				"organization_name":           config.EntityName,
			},
			"openid_provider": map[string]interface{}{
				"issuer":                                config.EntityID,
				"display_name":                          config.EntityName, // Add this
				"registration_endpoint":                 config.EntityID + "/register",
				"authorization_endpoint":                config.EntityID + "/authorize",
				"token_endpoint":                        config.EntityID + "/token",
				"userinfo_endpoint":                     config.EntityID + "/userinfo",
				"jwks_uri":                              config.EntityID + "/jwks",
				"response_types_supported":              upstreamMetadata["response_types_supported"],
				"subject_types_supported":               upstreamMetadata["subject_types_supported"],
				"id_token_signing_alg_values_supported": upstreamMetadata["id_token_signing_alg_values_supported"],
				"scopes_supported":                      upstreamMetadata["scopes_supported"],
				"token_endpoint_auth_methods_supported": upstreamMetadata["token_endpoint_auth_methods_supported"],
			},
		},
	}

	jwtTok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	jwtTok.Header["kid"] = kid
	jwtTok.Header["typ"] = "entity-statement+jwt"

	result, err := jwtTok.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return result, nil
}

func base64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// fetchSubordinateStatement fetches the entity statement from a subordinate
func fetchSubordinateStatement(entityID string) (map[string]interface{}, error) {
	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-federation", entityID)

	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subordinate statement: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subordinate statement request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read subordinate statement: %w", err)
	}

	// Parse the JWT
	parts := strings.Split(string(body), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format in subordinate statement")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode subordinate statement payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse subordinate statement claims: %w", err)
	}

	return claims, nil
}

// Add this helper function at the end of the file
func extractPublicKeyFromJWKS(jwksData map[string]interface{}, kid string) (interface{}, error) {
	if keys, ok := jwksData["keys"].([]interface{}); ok {
		for _, k := range keys {
			if keyMap, ok := k.(map[string]interface{}); ok {
				if keyMap["kid"] == kid {
					switch keyMap["kty"] {
					case "EC":
						crv, _ := keyMap["crv"].(string)
						xStr, _ := keyMap["x"].(string)
						yStr, _ := keyMap["y"].(string)
						xBytes, _ := base64.RawURLEncoding.DecodeString(xStr)
						yBytes, _ := base64.RawURLEncoding.DecodeString(yStr)
						x := new(big.Int).SetBytes(xBytes)
						y := new(big.Int).SetBytes(yBytes)
						var curve elliptic.Curve
						switch crv {
						case "P-256":
							curve = elliptic.P256()
						case "P-384":
							curve = elliptic.P384()
						case "P-521":
							curve = elliptic.P521()
						default:
							return nil, fmt.Errorf("unsupported EC curve: %s", crv)
						}
						pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
						return pubKey, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}

// Add min function if not already present
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function to get map keys for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// resolveEntityViaResolver resolves an entity using the federation resolver service
func resolveEntityViaResolver(entityID, trustAnchor, resolverURL string) (string, error) {
	if resolverURL == "" {
		return "", fmt.Errorf("resolver URL not configured")
	}

	// Build resolver API URL - use /api/v1/entity/ instead of /api/v1/resolve/
	resolveURL := fmt.Sprintf("%s/api/v1/entity/%s",
		resolverURL,
		url.QueryEscape(entityID))

	if trustAnchor != "" {
		resolveURL += fmt.Sprintf("/trust-anchor/%s", url.QueryEscape(trustAnchor))
	}

	log.Printf("[DEBUG] Resolving entity %s via resolver: %s", entityID, resolveURL)

	resp, err := http.Get(resolveURL)
	if err != nil {
		return "", fmt.Errorf("failed to call resolver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("resolver returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read resolver response: %w", err)
	}

	// Parse the JSON response from resolver
	var resolverResponse map[string]interface{}
	if err := json.Unmarshal(body, &resolverResponse); err != nil {
		return "", fmt.Errorf("failed to parse resolver JSON response: %w", err)
	}

	// Extract the JWT statement from the "statement" field
	statement, ok := resolverResponse["statement"].(string)
	if !ok {
		return "", fmt.Errorf("resolver response missing 'statement' field or not a string")
	}

	log.Printf("[DEBUG] Successfully extracted JWT statement from resolver response")
	return statement, nil
}
