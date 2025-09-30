package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// randomString generates a secure random string of length n
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// Config struct for OP settings
type Config struct {
	EntityID             string   `json:"entity_id"`
	TrustAnchors         []string `json:"trust_anchors"`
	UpstreamOIDCProvider string   `json:"upstream_oidc_provider"`
	UpstreamClientID     string   `json:"upstream_client_id"`
	UpstreamClientSecret string   `json:"upstream_client_secret"`
	Port                 int      `json:"port"`
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
	privateKey *ecdsa.PrivateKey
	publicKey  ecdsa.PublicKey
	jwks       map[string]interface{}
	kid        string

	// In-memory client registry: client_id -> struct with secret and allowed redirect_uris
	registeredClients = make(map[string]struct {
		EntityID     string
		Secret       string
		RedirectURIs []string
		RegisteredAt int64
	})
)

func main() {
	// Load config
	cfgData, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	if err := json.Unmarshal(cfgData, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Generate EC key
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
	var upstreamMetadata map[string]interface{}
	resp, err := http.Get(config.UpstreamOIDCProvider + "/.well-known/openid-configuration")
	if err != nil {
		log.Fatalf("Failed to fetch upstream OIDC discovery: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&upstreamMetadata); err != nil {
		log.Fatalf("Failed to decode upstream OIDC discovery: %v", err)
	}

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
			"trust_anchors":      config.TrustAnchors,
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
		log.Printf("[DEBUG] /resolve: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		sub := r.URL.Query().Get("sub")
		if sub == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "sub parameter required")
			return
		}
		if sub == config.EntityID {
			// Directly return OP's own entity statement
			jwtStr, err := buildEntityStatementDynamic(upstreamMetadata)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprint(w, err.Error())
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			fmt.Fprint(w, jwtStr)
			return
		}

		// Check if sub matches a registered RP
		for _, reg := range registeredClients {
			log.Println("[DEBUG] Checking registered client with redirect URIs:", reg.RedirectURIs)

			if reg.EntityID != sub {
				continue
			}

			log.Println("[DEBUG] Matched entity ID:", sub, "now checking redirect URIs...")
			for _, uri := range reg.RedirectURIs {
				log.Println("[DEBUG] Comparing with URI:", uri)

				if uri == sub {
					// Build entity statement for RP
					claims := jwt.MapClaims{
						"iss":             config.EntityID,
						"sub":             sub,
						"iat":             time.Now().Unix(),
						"exp":             time.Now().Add(24 * time.Hour).Unix(),
						"jwks":            jwks,
						"authority_hints": config.TrustAnchors,
						"metadata": map[string]interface{}{
							"openid_relying_party": map[string]interface{}{
								"redirect_uris": reg.RedirectURIs,
							},
						},
					}
					jwtTok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
					jwtTok.Header["kid"] = kid
					jwtTok.Header["typ"] = "entity-statement+jwt"
					jwtStr, err := jwtTok.SignedString(privateKey)
					if err != nil {
						log.Println("[DEBUG] Error signing JWT:", err)
						w.WriteHeader(500)
						fmt.Fprint(w, err.Error())
						return
					}
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Content-Type", "application/jwt")
					fmt.Fprint(w, jwtStr)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "No entity statement found for sub: %s", sub)
	})

	// OIDC dynamic client registration endpoint
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /register: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Debug: log raw request body
		var reqBody struct {
			RegistrationJWT string `json:"registration_jwt"`
		}
		rawBody, _ := io.ReadAll(r.Body)
		log.Printf("[DEBUG] /register raw request body: %s", string(rawBody))
		if err := json.Unmarshal(rawBody, &reqBody); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register invalid request body: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_request_body",
				"details": err.Error(),
			})
			return
		}
		// Parse JWT claims without validation to extract RP entity ID
		tokenUnverified, _, err := new(jwt.Parser).ParseUnverified(reqBody.RegistrationJWT, jwt.MapClaims{})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register invalid registration JWT: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_registration_jwt",
				"details": err.Error(),
			})
			return
		}
		claims, ok := tokenUnverified.Claims.(jwt.MapClaims)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register invalid JWT claims")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_jwt_claims",
				"details": "Could not parse JWT claims",
			})
			return
		}
		rpEntityID, ok := claims["iss"].(string)
		if !ok || rpEntityID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register missing or invalid iss claim")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_rp_entity_id",
				"details": "Missing or invalid iss claim",
			})
			return
		}
		// Fetch RP JWKS
		jwksURL := rpEntityID + "/jwks"
		jwksResp, err := http.Get(jwksURL)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register failed to fetch RP JWKS: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "failed_to_fetch_rp_jwks",
				"details": err.Error(),
			})
			return
		}
		defer jwksResp.Body.Close()
		var jwksData map[string]interface{}
		if err := json.NewDecoder(jwksResp.Body).Decode(&jwksData); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register failed to decode RP JWKS: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "failed_to_decode_rp_jwks",
				"details": err.Error(),
			})
			return
		}
		// Validate JWT signature using RP JWKS
		token, err := jwt.Parse(reqBody.RegistrationJWT, func(token *jwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
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
		})
		if err != nil || !token.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register invalid registration JWT signature: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_registration_jwt_signature",
				"details": err.Error(),
			})
			return
		}
		claims, ok = token.Claims.(jwt.MapClaims)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register invalid JWT claims after signature validation")
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
		aud, audOk := claims["aud"].(string)
		iss, issOk := claims["iss"].(string)
		if !expOk || !iatOk || !audOk || !issOk {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register missing required claims in JWT")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "invalid_jwt_claims",
				"details": "Missing exp, iat, aud, or iss claim",
			})
			return
		}
		if int64(exp) < now {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register JWT expired")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_expired",
				"details": "exp claim is in the past",
			})
			return
		}
		if int64(iat) > now {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register JWT issued in the future")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_iat_invalid",
				"details": "iat claim is in the future",
			})
			return
		}
		// Strict validation: aud must match config.ClientID, iss must not be empty
		if aud != config.EntityID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_aud_mismatch",
				"details": fmt.Sprintf("aud claim mismatch: got %s, expected %s", aud, config.EntityID),
			})
			return
		}
		if iss == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register JWT iss missing")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "jwt_iss_missing",
				"details": "iss claim is missing",
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("[DEBUG] /register RP not trusted by any configured trust anchor")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "rp_not_trusted",
				"details": "RP authority_hints do not match any trust anchor",
			})
			return
		}

		// Extract RP entity info
		redirectURIs := []string{}
		if meta, ok := claims["metadata"].(map[string]interface{}); ok {
			if rpMeta, ok := meta["openid_relying_party"].(map[string]interface{}); ok {
				if uris, ok := rpMeta["redirect_uris"].([]interface{}); ok {
					for _, uri := range uris {
						if s, ok := uri.(string); ok {
							redirectURIs = append(redirectURIs, s)
						}
					}
				}
			}
		}
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
		writeClientRegistrationResponse(w, generatedClientID, generatedClientSecret, issuedAt, redirectURIs, "new")
	})

	// Federation /list endpoint
	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] /list: %s %s from %s, params: %v", r.Method, r.URL.Path, r.RemoteAddr, r.URL.RawQuery)
		entities := map[string]interface{}{
			config.EntityID: map[string]interface{}{
				"metadata": map[string]interface{}{
					"openid_provider": map[string]interface{}{
						"issuer":                                config.EntityID,
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
			},
		}
		claims := jwt.MapClaims{
			"iss":      config.EntityID,
			"sub":      config.EntityID,
			"iat":      time.Now().Unix(),
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
			"entities": entities,
		}
		jwtTok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		jwtTok.Header["kid"] = kid
		jwtTok.Header["typ"] = "entity-list+jwt"
		jwtStr, err := jwtTok.SignedString(privateKey)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, err.Error())
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/jwt")
		fmt.Fprint(w, jwtStr)
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

	addr := fmt.Sprintf(":%d", config.Port)
	log.Printf("Federation-compliant Test OP running on %s", addr)
	http.ListenAndServe(addr, nil)
}

func writeClientRegistrationResponse(w http.ResponseWriter, clientID, clientSecret string, issuedAt int64, redirectURIs []string, mode string) {
	resp := map[string]interface{}{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"client_id_issued_at":        issuedAt,
		"redirect_uris":              redirectURIs,
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      "openid profile email",
	}
	w.Header().Set("Content-Type", "application/json")
	log.Printf("[DEBUG] /register %s client response: %+v", mode, resp)
	json.NewEncoder(w).Encode(resp)
}

func buildEntityStatementDynamic(upstreamMetadata map[string]interface{}) (string, error) {
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
			},
			"openid_provider": map[string]interface{}{
				"issuer":                                config.EntityID,
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
	return jwtTok.SignedString(privateKey)
}

func base64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
