# eBPF dasturini kompilyatsiya qilish uchun muhit.
#
# Nega konteyner: clang va libbpf sarlavhalari host'da bo'lmasligi
# mumkin (macOS'da umuman yo'q). Natija — .o fayl — repoga commit
# qilinadi, ya'ni `go build` uchun clang KERAK EMAS. Xuddi protobuf
# generatsiyasi kabi.
FROM ubuntu:24.04

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      clang llvm libbpf-dev linux-libc-dev make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
