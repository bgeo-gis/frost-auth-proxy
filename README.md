1. Add it to docker compose:
   ```
   frost-auth-proxy:
    build: ../frost-auth-proxy/
    environment:
      FROST_SERVER_BASE: '' # TODO
      AUTH_REQUIRED: True
      <<: *qwc-service-variables
   ```
2. Add the location in the Nginx configuration
   ```
   location ~ ^/(?<t>tenant1|tenant2)/frost_auth_proxy {
       proxy_set_header Tenant $t;
       rewrite ^/[^/]+/frost_auth_proxy/?(.*)$ /$1 break;
       proxy_pass http://frost-auth-proxy:9090;

       # optional but nice: preserve real client IP chain
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
   }
   ```
3. Replace the FROST URL in your QWC2 layer configuration:
   - Before: `https://frost.example.com/FROST-Server/v1.1/...`
   - After: `https://www.example.com/tenant1/frost_auth_proxy/FROST-Server/v1.1/...`


Environment

- Required:
  - FROST_SERVER_BASE: Upstream FROST server base URL (http(s)://host[:port][/basepath])
  - JWT_SECRET_KEY: HS256 secret for verifying JWTs
- Optional:
  - PORT: Listen port (default: 9090)
  - AUTH_REQUIRED: true/false (default: true)
  - JWT_ACCESS_COOKIE_NAME: cookie name to read JWT from (default: access_token_cookie)
  - CONNECT_TIMEOUT: e.g. 2s (default: 2s)
  - RESPONSE_HEADER_TIMEOUT: e.g. 15s (default: 15s)
  - PROXY_BASE_URL: Public base URL for this proxy. When set, JSON responses will have
    upstream URLs rewritten to this base (http(s)://host[:port][/basepath]).
