# Zot Token Service

A small, stateless token service for a [Zot](https://zotregistry.dev/) OCI registry behind a reverse proxy.

It implements the Docker Registry v2 token flow and an `/authz` endpoint for a proxy to authorize registry requests. Anonymous clients receive pull-only tokens. Push requests require HTTP Basic credentials that Zot accepts. The service stores accepted upstream credentials only inside an AES-GCM encrypted, short-lived token, then returns them to the proxy after authorization.

## Run

The service requires a Base64-encoded 32-byte AES key. Generate one for each deployment:

```sh
export TOKEN_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export REGISTRY_SERVICE=registry.example.com
export REGISTRY_REALM=https://registry.example.com/token
export ZOT_URL=http://zot:5000
go run .
```

It listens on `:8080` by default. Available endpoints:

- `GET /token` — Docker Registry token endpoint.
- `GET /v2/` — registry API ping and Bearer challenge.
- `/authz` — reverse-proxy authorization endpoint. The proxy must provide `X-Original-Method`, `X-Original-URI`, and, when applicable, the original authorization headers.
- `GET /livez` and `GET /healthz` — liveness and Zot dependency readiness probes.

See [`.env.example`](.env.example) for every supported setting.

## Container image

```sh
docker build -t zot-token-service .
docker run --rm -p 8080:8080 --env-file .env zot-token-service
```

The image is built `FROM scratch`, runs as an unprivileged user, and exposes only port 8080.

## Development

```sh
go test ./...
go vet ./...
go build ./...
```

## Security notes

- Keep `TOKEN_ENCRYPTION_KEY` secret and stable for the lifetime of issued tokens. Rotating it invalidates existing tokens.
- Terminate TLS at the reverse proxy. Do not expose this service directly to the public internet.
- Configure the proxy to prevent clients from injecting the internal `X-Original-*`, `X-ZOT-*`, or upstream-authorization headers.
- Use a short `TOKEN_TTL`; the default is 15 minutes.

## License

Licensed under the [Apache License 2.0](LICENSE).
