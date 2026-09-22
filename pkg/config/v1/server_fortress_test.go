package v1

import "testing"

func TestTrustedCAForcesTLSUnlessPlaintextAllowed(t *testing.T) {
	forced := &ServerTransportConfig{}
	forced.TLS.TrustedCaFile = "ca.crt"
	forced.Complete()
	if !forced.TLS.Force {
		t.Fatal("TrustedCaFile did not set Force")
	}

	plain := &ServerTransportConfig{}
	plain.TLS.TrustedCaFile = "ca.crt"
	plain.TLS.AllowPlaintext = true
	plain.Complete()
	if plain.TLS.Force {
		t.Fatal("AllowPlaintext still forced TLS on the control port")
	}
}

func TestQUICBindAddrDefaultsToBindAddr(t *testing.T) {
	same := &ServerConfig{BindAddr: "127.0.0.1"}
	if err := same.Complete(); err != nil {
		t.Fatal(err)
	}
	if same.QUICBindAddr != "127.0.0.1" {
		t.Fatalf("QUICBindAddr = %q", same.QUICBindAddr)
	}

	split := &ServerConfig{BindAddr: "127.0.0.1", QUICBindAddr: "0.0.0.0"}
	if err := split.Complete(); err != nil {
		t.Fatal(err)
	}
	if split.BindAddr != "127.0.0.1" || split.QUICBindAddr != "0.0.0.0" {
		t.Fatalf("bind %q quic %q", split.BindAddr, split.QUICBindAddr)
	}
}
