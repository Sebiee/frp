package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerCertReread(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	writeCert(t, certPath, keyPath, "first.example")

	cfg, err := NewServerTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn(t, first) != "first.example" {
		t.Fatalf("cn %q", cn(t, first))
	}

	writeCert(t, certPath, keyPath, "second.example")
	second, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn(t, second) != "second.example" {
		t.Fatalf("cn %q", cn(t, second))
	}
}

func TestGetCertificateSkipsFiles(t *testing.T) {
	sentinel := &tls.Certificate{}
	cfg, err := NewServerTLSConfigWith("", "", "", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return sentinel, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != sentinel {
		t.Fatal("callback cert was not used")
	}
	if len(cfg.Certificates) != 0 {
		t.Fatal("files were loaded beside the callback")
	}
}

func cn(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject.CommonName
}

func writeCert(t *testing.T, certPath, keyPath, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
