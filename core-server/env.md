# Environment Variables

This project currently uses 3 environment variables.

## `CC01_DOMAIN`
- Used in `core-server/config/config.go`
- Purpose: base domain for all public tunnel hostnames
- Example: if this is `example.com`, a tunnel subdomain like `demo` becomes `demo.example.com`
- Required: yes

## `CC01_TLS_CERT`
- Used in `core-server/config/config.go`
- Purpose: path to the TLS certificate file for the HTTPS listener
- Required: yes

## `CC01_TLS_KEY`
- Used in `core-server/config/config.go`
- Purpose: path to the TLS private key file for the HTTPS listener
- Required: yes

## Not an env variable, but important config

### Fixed runtime values
- `MaxConsPerTunnel = 24`
- `EventServerPort = 4321`
- `PublicServerPort = 80`
- `PublicServerTLSPort = 443`

These are hardcoded in `core-server/config/config.go`, so they are not part of `env.example` yet.
