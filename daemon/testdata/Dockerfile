# cc01d demo — mesh datapath'ni ikkita konteynerda sinash uchun.
FROM golang:1.25 AS build
WORKDIR /src
COPY daemon/go.mod daemon/go.sum ./daemon/
WORKDIR /src/daemon
RUN GOWORK=off go mod download
COPY daemon/ ./
RUN GOWORK=off CGO_ENABLED=0 go build -o /out/cc01d ./cmd/cc01d

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cc01d /usr/local/bin/cc01d
ENTRYPOINT ["cc01d"]
