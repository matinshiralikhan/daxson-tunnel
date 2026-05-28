// Package transport defines the pluggable transport interface.
// Each transport handles raw connection establishment; higher layers
// (obfuscation, multiplexing) are applied on top.
package transport

import (
	"context"
	"net"
)

// Transport is the interface all transports must implement.
type Transport interface {
	// Dial opens a new outbound connection to addr.
	Dial(ctx context.Context, addr string) (net.Conn, error)
	// Listen creates a new listener bound to addr.
	Listen(addr string) (net.Listener, error)
	// Name returns a human-readable transport identifier.
	Name() string
}

// Registry maps transport names to their factories.
var Registry = map[string]Transport{}

// Register adds a transport to the global registry.
func Register(t Transport) {
	Registry[t.Name()] = t
}
