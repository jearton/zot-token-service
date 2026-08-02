ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED
ARG SOURCE_URL=https://github.com/jearton/zot-token-service

FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS source

ARG VERSION
ARG REVISION

WORKDIR /src
COPY go.mod ./
COPY src/ ./src/

FROM source AS test

RUN unformatted="$(gofmt -l ./src)"; \
    test -z "$unformatted" || { printf 'Unformatted Go files:\n%s\n' "$unformatted"; exit 1; }
RUN go test ./...
RUN go vet ./...
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildRevision=${REVISION}" \
  -o /tmp/zot-token-service ./src

FROM source AS build

RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildRevision=${REVISION}" \
  -o /out/zot-token-service ./src

FROM scratch

ARG VERSION
ARG REVISION
ARG CREATED
ARG SOURCE_URL

LABEL org.opencontainers.image.title="zot-token-service" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --from=build /out/zot-token-service /usr/local/bin/zot-token-service
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/zot-token-service", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/zot-token-service"]
