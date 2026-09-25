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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSigned is a self-signed certificate for name, and its PEM.
func selfSigned(t *testing.T, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// handshake runs a TLS handshake between client and a server presenting cert.
func handshake(t *testing.T, client *tls.Config, cert tls.Certificate) error {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		srv := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = srv.Handshake()
		srv.Close()
	}()
	return tls.Client(c, client).Handshake()
}

// A client verifies the server: against trustedCaFile, or against the
// system roots when there is none. Nothing is skipped unless asked.
func TestClientVerifiesTheServer(t *testing.T) {
	cert, certPEM := selfSigned(t, "edge.example.com")
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	noCA, err := NewClientTLSConfig("", "", "", "edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if noCA.InsecureSkipVerify || noCA.RootCAs != nil {
		t.Fatal("no trustedCaFile must verify against the system roots")
	}
	if err := handshake(t, noCA, cert); err == nil {
		t.Fatal("a self-signed server was accepted without a trustedCaFile")
	}

	withCA, err := NewClientTLSConfig("", "", ca, "edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, withCA, cert); err != nil {
		t.Fatalf("the trusted CA's server: %v", err)
	}
	otherName, err := NewClientTLSConfig("", "", ca, "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, otherName, cert); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}

	skip, err := NewClientTLSConfig("", "", "", "edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	skip.InsecureSkipVerify = true
	if err := handshake(t, skip, cert); err != nil {
		t.Fatalf("insecureSkipVerify: %v", err)
	}
}
