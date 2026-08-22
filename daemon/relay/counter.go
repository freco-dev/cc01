package relay

import "sync/atomic"

// atomicCounter — statistika uchun oddiy hisoblagich.
type atomicCounter struct{ value atomic.Int64 }

func (c *atomicCounter) add(delta int64) { c.value.Add(delta) }
func (c *atomicCounter) load() int64     { return c.value.Load() }
