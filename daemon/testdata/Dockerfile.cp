# cc01-cp + cc01d — Control Plane bilan avtomatik mesh demosi.
FROM golang:1.25 AS build
WORKDIR /src
COPY proto/ ./proto/
COPY daemon/ ./daemon/
COPY control/ ./control/
RUN cd daemon  && GOWORK=off CGO_ENABLED=0 go build -o /out/cc01d   ./cmd/cc01d \
 && GOWORK=off CGO_ENABLED=0 go build -o /out/cc01 ./cmd/cc01
RUN cd control && GOWORK=off CGO_ENABLED=0 go build -o /out/cc01-cp ./cmd/cc01-cp

FROM debian:stable-slim
# iproute2/iptables NAT demosi uchun: shlyuz konteynerida marshrut va
# MASQUERADE sozlanadi (daemon/testdata/nat-demo.sh).
RUN apt-get update && apt-get install -y --no-install-recommends \
      iputils-ping iproute2 iptables procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cc01d   /usr/local/bin/cc01d
COPY --from=build /out/cc01    /usr/local/bin/cc01
COPY --from=build /out/cc01-cp /usr/local/bin/cc01-cp
