package ipc

import (
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// insecureCreds — UNIX soketi uchun TLS kerak emas.
//
// Kanal mashinadan chiqmaydi: himoyani soket ruxsatlari beradi, ya'ni
// TLS qo'shimcha xavfsizlik bermaydi, faqat murakkablik qo'shadi.
func insecureCreds() credentials.TransportCredentials {
	return insecure.NewCredentials()
}
