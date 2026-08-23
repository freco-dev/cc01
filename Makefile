# cc01 — monorepo build fayli.  `make help` — mavjud buyruqlar ro'yxati.

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO_MODULES  := ./proto/... ./core-server/... ./cli-client/... ./daemon/... ./control/...
PROTO_DIR   := proto
DOTNET_SLN  := access-server/AccessServer.slnx

# ── Docker ────────────────────────────────────────────────────────────────
# DIQQAT: bu mashinada standart docker konteksti masofaviy serverga qaratilgan
# bo'lishi mumkin. Dev muhitni xato bilan prod serverda ko'tarib yubormaslik
# uchun `check-docker` maqsadi endpoint lokal ekanini tekshiradi.
DOCKER_CONTEXT ?= desktop-linux
DOCKER         := docker --context $(DOCKER_CONTEXT)

# buf lokal o'rnatilgan bo'lsa undan, aks holda konteynerdan foydalanamiz.
BUF_LOCAL := $(shell command -v buf 2>/dev/null)
ifeq ($(BUF_LOCAL),)
  BUF := $(DOCKER) run --rm -v "$(CURDIR)":/workspace -w /workspace/$(PROTO_DIR) bufbuild/buf:latest
  BUF_NEEDS_DOCKER := 1
else
  BUF := cd $(PROTO_DIR) && buf
endif

.PHONY: help
help: ## Shu ro'yxatni ko'rsatadi
	@echo "cc01 — mavjud buyruqlar:"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Docker konteksti: $(DOCKER_CONTEXT)  (o'zgartirish: make <target> DOCKER_CONTEXT=<nom>)"

# ── Go ────────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Go binarlarini quradi
	go build $(GO_MODULES)

.PHONY: test
test: ## Go testlarini ishga tushiradi
	go test $(GO_MODULES)

.PHONY: vet
vet: ## go vet
	go vet $(GO_MODULES)

.PHONY: lint
lint: vet ## golangci-lint (o'rnatilgan bo'lsa) + go vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run $(GO_MODULES); \
	else \
	  echo "⚠ golangci-lint o'rnatilmagan — faqat go vet bajarildi."; \
	  echo "  O'rnatish: https://golangci-lint.run/welcome/install/"; \
	fi

.PHONY: check-modules
check-modules: ## Har bir modul workspace'siz ham quriladimi
	@echo "go.work modullar orasidagi bog'liqlikni yashiradi —"
	@echo "Docker build esa GOWORK=off bilan ishlaydi, shuning uchun"
	@echo "har bir modulni alohida tekshiramiz."
	@for m in proto core-server cli-client daemon control; do \
	  printf "  %-12s " "$$m"; \
	  (cd $$m && GOWORK=off go build ./... >/dev/null 2>&1) && echo "OK" \
	    || { echo "FAIL"; exit 1; }; \
	done

.PHONY: tidy
tidy: ## Har bir modulda go mod tidy
	cd core-server && go mod tidy
	cd cli-client && go mod tidy
	cd daemon && go mod tidy
	cd control && go mod tidy
	cd proto && go mod tidy

# ── Proto ─────────────────────────────────────────────────────────────────

.PHONY: proto
proto: proto-lint ## Proto'dan Go kodini generatsiya qiladi (core-server/gen)
	$(BUF) generate
	@echo "✔ generatsiya tugadi. Natija commit qilinadi: go build codegen"
	@echo "  vositalarisiz ham ishlashi kerak."

.PHONY: proto-lint
proto-lint: $(if $(BUF_NEEDS_DOCKER),check-docker) ## buf lint
	$(BUF) lint

.PHONY: proto-breaking
proto-breaking: $(if $(BUF_NEEDS_DOCKER),check-docker) ## Orqaga moslik buzilganini tekshiradi (main'ga nisbatan)
	$(BUF) breaking --against '../.git#branch=main,subdir=proto'

.PHONY: test-linux
test-linux: check-docker ## Imtiyozli TUN testlarini Linux konteynerida ishga tushiradi
	@echo "TUN testlari CAP_NET_ADMIN va /dev/net/tun talab qiladi —"
	@echo "shuning uchun ular Linux konteynerida bajariladi."
	$(DOCKER) run --rm --cap-add NET_ADMIN --device /dev/net/tun \
	  -v "$(CURDIR)":/src -w /src/daemon \
	  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
	  golang:1.25 sh -c 'go vet ./... && go test -race -count=1 ./...'

.PHONY: mesh-demo
mesh-demo: check-docker ## Ikkita konteynerda shifrlangan overlay va ping6
	sh daemon/testdata/mesh-demo.sh

.PHONY: cp-demo
cp-demo: check-docker ## Control Plane + 3 node: qo'lda konfiguratsiyasiz mesh
	sh daemon/testdata/cp-demo.sh

.PHONY: nat-demo
nat-demo: check-docker ## NAT ortidagi node: STUN bilan ikki tomonlama ulanish
	sh daemon/testdata/nat-demo.sh

.PHONY: relay-demo
relay-demo: check-docker ## Ikkita node har biri o'z NAT'i ortida: relay orqali
	sh daemon/testdata/relay-demo.sh

.PHONY: punch-demo
punch-demo: check-docker ## NAT teshish: relaydan boshlab to'g'ridan-to'g'ri yo'lga o'tish
	sh daemon/testdata/punch-demo.sh

# ── Paketlar (deb/rpm) ────────────────────────────────────────────────────
# Binarlar konteynerda quriladi: host macOS bo'lishi mumkin, paketga
# esa Linux binari kerak. nfpm bitta tavsifdan ikkala formatni beradi.
# Paket versiyasi. deb raqam bilan boshlanishini talab qiladi, rpm esa
# `-` ni ajratuvchi deb o'qiydi — shuning uchun teg yo'q bo'lganda
# xeshni 0.0.0 ostiga qo'yamiz va `-` ishlatmaymiz.
GIT_TAG   := $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_SHA   := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
GIT_DIRTY := $(shell git diff --quiet 2>/dev/null || echo .dirty)

ifeq ($(GIT_TAG),)
  VERSION ?= 0.0.0+g$(GIT_SHA)$(GIT_DIRTY)
else
  VERSION ?= $(patsubst v%,%,$(GIT_TAG))$(GIT_DIRTY)
endif
PKG_ARCH ?= amd64 arm64

.PHONY: package
package: check-docker ## deb va rpm paketlarini quradi (dist/)
	@for arch in $(PKG_ARCH); do \
	  echo "→ $$arch binarlari"; \
	  rm -rf dist/stage; mkdir -p dist/stage; \
	  $(DOCKER) run --rm -v "$(CURDIR)":/src -w /src/daemon \
	    -e GOWORK=off -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=$$arch \
	    -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
	    golang:1.25 sh -c \
	      'go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
	         -o /src/dist/stage/cc01d ./cmd/cc01d && \
	       go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
	         -o /src/dist/stage/cc01  ./cmd/cc01' || exit 1; \
	  echo "→ $$arch paketlari"; \
	  for format in deb rpm; do \
	    $(DOCKER) run --rm -v "$(CURDIR)":/src -w /src \
	      -e ARCH=$$arch -e VERSION=$(VERSION) \
	      goreleaser/nfpm:latest package \
	      --config deploy/packaging/nfpm.yaml --target dist --packager $$format || exit 1; \
	  done; \
	done
	@rm -rf dist/stage
	@echo
	@ls -1 dist/*.deb dist/*.rpm

.PHONY: package-verify
package-verify: check-docker ## Paketni toza konteynerda o'rnatib tekshiradi
	sh deploy/packaging/verify.sh

# ── .NET (access-server) ──────────────────────────────────────────────────

.PHONY: dotnet-build
dotnet-build: ## access-server'ni quradi
	dotnet build $(DOTNET_SLN) --nologo -warnaserror

.PHONY: dotnet-test
dotnet-test: ## access-server testlari
	dotnet test $(DOTNET_SLN) --nologo

.PHONY: dotnet-format
dotnet-format: ## C# formatini tekshiradi (o'zgartirmaydi)
	dotnet format $(DOTNET_SLN) --verify-no-changes

.PHONY: dotnet-vuln
dotnet-vuln: ## Zaif NuGet paketlarini qidiradi (§7.2 S-9)
	@out=$$(dotnet list $(DOTNET_SLN) package --vulnerable --include-transitive 2>&1); \
	echo "$$out"; \
	if echo "$$out" | grep -qE 'High|Critical'; then \
	  echo "✘ Yuqori/kritik zaiflik topildi — reliz bloklanadi."; exit 1; \
	fi

# ── Baza (EF Core migratsiyalari) ─────────────────────────────────────────
# Ulanish satri: CC01_ACCESS_DB muhit o'zgaruvchisi, aks holda dev default
# (AccessDbContextFactory ichida). Migratsiya deploy'dan ALOHIDA qadam
# (DEV_SPEC §6.5 A-S10) — shuning uchun alohida maqsadlar.
EF := cd access-server && dotnet dotnet-ef
EF_PROJECT := --project src/AccessServer.Infrastructure

.PHONY: db-migrate
db-migrate: ## Yangi migratsiya yaratadi:  make db-migrate NAME=AddPlans
	@if [ -z "$(NAME)" ]; then \
	  echo "✘ NAME kerak. Masalan: make db-migrate NAME=AddPlans"; exit 1; \
	fi
	$(EF) migrations add $(NAME) $(EF_PROJECT) --output-dir Persistence/Migrations

.PHONY: db-update
db-update: ## Migratsiyalarni bazaga qo'llaydi
	$(EF) database update $(EF_PROJECT)

.PHONY: db-down
db-down: ## Hamma migratsiyani qaytaradi (bo'sh bazaga)
	$(EF) database update 0 $(EF_PROJECT)

.PHONY: db-verify
db-verify: ## DoD talabi: up → down → up ishlashini tekshiradi
	@echo "→ up";   $(EF) database update 0 $(EF_PROJECT) >/dev/null
	@$(EF) database update $(EF_PROJECT) >/dev/null && echo "  ✔ up OK"
	@echo "→ down"; $(EF) database update 0 $(EF_PROJECT) >/dev/null && echo "  ✔ down OK"
	@echo "→ up";   $(EF) database update $(EF_PROJECT) >/dev/null && echo "  ✔ qayta up OK"

.PHONY: db-sql
db-sql: ## Migratsiyalarni SQL ko'rinishida chiqaradi (review uchun)
	$(EF) migrations script $(EF_PROJECT) --idempotent

# ── Dev muhit ─────────────────────────────────────────────────────────────

.PHONY: check-docker
check-docker: ## Docker konteksti lokal ekanini tekshiradi
	@endpoint=$$(docker context inspect $(DOCKER_CONTEXT) --format '{{.Endpoints.docker.Host}}' 2>/dev/null); \
	if [ -z "$$endpoint" ]; then \
	  echo "✘ Docker konteksti topilmadi: $(DOCKER_CONTEXT)"; \
	  echo "  Mavjudlari:"; docker context ls --format '    {{.Name}}  {{.DockerEndpoint}}'; \
	  exit 1; \
	fi; \
	case "$$endpoint" in \
	  unix://*|npipe://*) ;; \
	  *) echo "✘ '$(DOCKER_CONTEXT)' konteksti LOKAL EMAS: $$endpoint"; \
	     echo "  Dev muhitni masofaviy serverda ko'tarib yubormaslik uchun to'xtatildi."; \
	     echo "  Lokal kontekstni ko'rsating, masalan:"; \
	     echo "      make dev-up DOCKER_CONTEXT=desktop-linux"; \
	     exit 1 ;; \
	esac

.PHONY: dev-up
dev-up: check-docker ## Dev bog'liqliklarini ko'taradi (postgres + redis)
	$(DOCKER) compose -f deploy/docker-compose.dev.yml up -d
	@echo "✔ postgres :15432, redis :16379"

.PHONY: dev-down
dev-down: check-docker ## Dev muhitni to'xtatadi
	$(DOCKER) compose -f deploy/docker-compose.dev.yml down

.PHONY: dev-reset
dev-reset: check-docker ## Dev muhitni volume'lari bilan o'chiradi
	$(DOCKER) compose -f deploy/docker-compose.dev.yml down -v

# ── Yig'ma ────────────────────────────────────────────────────────────────

.PHONY: check
check: lint test check-modules proto-lint dotnet-build dotnet-test dotnet-vuln ## CI bajaradigan hamma tekshiruv

.PHONY: clean
clean: ## Build artefaktlarini tozalaydi
	go clean -cache -testcache
	rm -rf dist
	dotnet clean $(DOTNET_SLN) --nologo || true
