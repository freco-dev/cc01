package cluster

import (
	"context"
	"fmt"
	"sync"
)

// MemoryIdentities — klastersiz rejim uchun bog'lanishlar ombori.
//
// ⚠️ Jarayon qayta ishga tushganda bog'lanishlar YO'QOLADI va hamma
// node qaytadan token bilan ro'yxatdan o'tishi kerak bo'ladi. Ya'ni
// bu rejimda sertifikat himoyasi jarayon umridan uzoq yashamaydi.
// Ishlab chiqarish uchun klaster kerak.
type MemoryIdentities struct {
	mu     sync.RWMutex
	byNode map[string]string
}

func NewMemoryIdentities() *MemoryIdentities {
	return &MemoryIdentities{byNode: make(map[string]string)}
}

func (m *MemoryIdentities) Bind(_ context.Context, nodeID, certPin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.byNode[nodeID]; ok && existing != certPin {
		return fmt.Errorf("%w: %s", ErrIdentityMismatch, nodeID)
	}

	m.byNode[nodeID] = certPin
	return nil
}

func (m *MemoryIdentities) Identity(_ context.Context, nodeID string) (string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pin, ok := m.byNode[nodeID]
	return pin, ok, nil
}

var _ IdentityStore = (*MemoryIdentities)(nil)
