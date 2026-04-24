package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type config struct {
	listenAddr         string
	frostServerBase    *url.URL
	authRequired       bool
	jwtSecretKey       []byte
	jwtAccessCookie    string
	connectTimeout     time.Duration
	responseHdrTimeout time.Duration
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.responseHdrTimeout,
	}

	proxy := newReverseProxy(cfg.frostServerBase, transport, cfg.jwtAccessCookie)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cfg.authRequired {
			token := extractToken(r, cfg.jwtAccessCookie)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := verifyJWT(token, cfg.jwtSecretKey); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", cfg.listenAddr)
	log.Printf("proxying to %s", cfg.frostServerBase.String())
	if cfg.authRequired {
		log.Printf("auth required: true")
	} else {
		log.Printf("auth required: false")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func loadConfig() (*config, error) {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "9090"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid PORT %q", port)
	}

	frostBaseRaw := strings.TrimSpace(os.Getenv("FROST_SERVER_BASE"))
	if frostBaseRaw == "" {
		return nil, fmt.Errorf("FROST_SERVER_BASE is required")
	}
	frostBaseURL, err := url.Parse(frostBaseRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid FROST_SERVER_BASE: %w", err)
	}
	if frostBaseURL.Scheme != "http" && frostBaseURL.Scheme != "https" {
		return nil, fmt.Errorf("FROST_SERVER_BASE must be http(s)")
	}
	if frostBaseURL.Host == "" {
		return nil, fmt.Errorf("FROST_SERVER_BASE missing host")
	}
	frostBaseURL.Path = strings.TrimRight(frostBaseURL.Path, "/")

	authRequired := parseBoolEnv("AUTH_REQUIRED", true)
	jwtAccessCookie := strings.TrimSpace(os.Getenv("JWT_ACCESS_COOKIE_NAME"))
	if jwtAccessCookie == "" {
		jwtAccessCookie = "access_token_cookie"
	}

	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_KEY"))
	if authRequired && secret == "" {
		return nil, fmt.Errorf("JWT_SECRET_KEY is required when AUTH_REQUIRED=true")
	}

	connectTimeout := parseDurationEnv("CONNECT_TIMEOUT", 2*time.Second)
	responseHdrTimeout := parseDurationEnv("RESPONSE_HEADER_TIMEOUT", 15*time.Second)

	return &config{
		listenAddr:         ":" + port,
		frostServerBase:    frostBaseURL,
		authRequired:       authRequired,
		jwtSecretKey:       []byte(secret),
		jwtAccessCookie:    jwtAccessCookie,
		connectTimeout:     connectTimeout,
		responseHdrTimeout: responseHdrTimeout,
	}, nil
}

func parseBoolEnv(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	raw = strings.ToLower(raw)
	switch raw {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	default:
		return def
	}
}

func parseDurationEnv(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	if d <= 0 {
		return def
	}
	return d
}

func newReverseProxy(targetBase *url.URL, transport http.RoundTripper, jwtCookieName string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetBase)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		incomingRawQuery := r.URL.RawQuery
		originalDirector(r)

		// Keep incoming query string untouched.
		r.URL.RawQuery = incomingRawQuery

		// Avoid leaking auth.
		r.Header.Del("Authorization")
		stripCookie(r, jwtCookieName)

		// Explicitly set Host header for upstream.
		r.Host = targetBase.Host

		// X-Forwarded-For: append client IP.
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			prior := r.Header.Get("X-Forwarded-For")
			if prior == "" {
				r.Header.Set("X-Forwarded-For", ip)
			} else {
				r.Header.Set("X-Forwarded-For", prior+", "+ip)
			}
		}
	}
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		return nil
	}

	return proxy
}

func extractToken(r *http.Request, cookieName string) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		tok := strings.TrimSpace(auth[len("bearer "):])
		if tok != "" {
			return tok
		}
	}

	if c, err := r.Cookie(cookieName); err == nil {
		if strings.TrimSpace(c.Value) != "" {
			return strings.TrimSpace(c.Value)
		}
	}

	return ""
}

func verifyJWT(tokenString string, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("empty secret")
	}
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		// Only accept HS256.
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %s", t.Method.Alg())
		}
		return secret, nil
	},
		jwt.WithLeeway(30*time.Second),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func stripCookie(r *http.Request, cookieName string) {
	raw := r.Header.Get("Cookie")
	if raw == "" {
		return
	}

	parts := strings.Split(raw, ";")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		name := strings.TrimSpace(kv[0])
		if name == cookieName {
			continue
		}
		kept = append(kept, p)
	}

	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecordingWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, dur)
	})
}

type statusRecordingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusRecordingWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
