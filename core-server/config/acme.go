package config

import "github.com/caddyserver/certmagic"

// acmeStagingCA — Let's Encrypt sinov katalogi.
//
// Alohida faylda: config paketi shu bitta doimiy uchun certmagic
// ga bog'lanadi va bog'liqlik qayerdan kelganini ko'rsatib turish
// afzal.
const acmeStagingCA = certmagic.LetsEncryptStagingCA
