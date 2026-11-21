package sentinel

import (
	"errors"
	"testing"
)

func TestLoopbackOnlyRefusesOtherMachines(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8787", "127.0.0.53:53", "[::1]:8787", "[::ffff:127.0.0.1]:8787"} {
		if err := loopbackOnly("tcp", addr, nil); err != nil {
			t.Errorf("loopbackOnly(%s) = %v, want nil", addr, err)
		}
	}
	for _, addr := range []string{"203.0.113.1:443", "[2001:db8::1]:443", "192.168.1.1:8787", "0.0.0.0:8787", "localhost:8787"} {
		if err := loopbackOnly("tcp", addr, nil); !errors.Is(err, ErrNotLoopback) {
			t.Errorf("loopbackOnly(%s) = %v, want ErrNotLoopback", addr, err)
		}
	}
}
