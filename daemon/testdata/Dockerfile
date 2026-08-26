# cc01d demo — mesh datapath'ni ikkita konteynerda sinash uchun.
#
# `proto` moduli ham nusxalanadi: daemon unga `replace ../proto` orqali
# bog'langan va GOWORK=off bilan qurishda u yonida turishi kerak.
FROM golang:1.25 AS build
WORKDIR /src
COPY proto/ ./proto/
COPY daemon/ ./daemon/
RUN cd daemon \
 && GOWORK=off CGO_ENABLED=0 go build -o /out/cc01d ./cmd/cc01d \
 && GOWORK=off CGO_ENABLED=0 go build -o /out/cc01  ./cmd/cc01

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cc01d /usr/local/bin/cc01d
COPY --from=build /out/cc01  /usr/local/bin/cc01
ENTRYPOINT ["cc01d"]
