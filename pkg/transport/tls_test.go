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

// The certificate request names no CA, and the chain is still checked as
// tls.RequireAndVerifyClientCert would: our CA, client auth, in date.
func TestServerAsksForAClientCertificateWithoutNamingCAs(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	writeCert(t, certPath, keyPath, "edge.example")
	ca, caKey := newCA(t, "fortressedge-ca")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewServerTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientCAs != nil {
		t.Fatal("ClientCAs set: the certificate request names them")
	}
	other, otherKey := newCA(t, "another-ca")
	// The same name as ours, another key: only the signature tells them apart.
	twin, twinKey := newCA(t, "fortressedge-ca")
	now := time.Now()
	for _, tc := range []struct {
		name string
		cert *tls.Certificate
		ok   bool
	}{
		{"none", nil, false},
		{"ours", leaf(t, ca, caKey, now, x509.ExtKeyUsageClientAuth), true},
		{"another CA's", leaf(t, other, otherKey, now, x509.ExtKeyUsageClientAuth), false},
		{"a CA with our name and another key", leaf(t, twin, twinKey, now, x509.ExtKeyUsageClientAuth), false},
		{"expired", leaf(t, ca, caKey, now.Add(-48*time.Hour), x509.ExtKeyUsageClientAuth), false},
		{"for servers only", leaf(t, ca, caKey, now, x509.ExtKeyUsageServerAuth), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var named [][]byte
			asked := false
			client := &tls.Config{InsecureSkipVerify: true, GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				asked, named = true, cri.AcceptableCAs
				if tc.cert == nil {
					return &tls.Certificate{}, nil
				}
				return tc.cert, nil
			}}
			err := clientAuthHandshake(t, cfg, client)
			if !asked {
				t.Fatal("the server asked for no client certificate")
			}
			if len(named) != 0 {
				t.Fatalf("the certificate request named %d CAs", len(named))
			}
			if tc.ok != (err == nil) {
				t.Fatalf("handshake: %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// clientAuthHandshake runs both ends over a pipe and returns the client's error, or
// the server's when the client saw none.
func clientAuthHandshake(t *testing.T, server, client *tls.Config) error {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	srvErr := make(chan error, 1)
	go func() {
		conn := tls.Server(s, server)
		err := conn.Handshake()
		if err == nil {
			// TLS 1.3: the client's certificate is checked after the
			// client's handshake ends; a read sees the outcome.
			_, err = conn.Write([]byte("x"))
		}
		srvErr <- err
		s.Close()
	}()
	conn := tls.Client(c, client)
	err := conn.Handshake()
	if err == nil {
		_, err = conn.Read(make([]byte, 1))
	}
	if serr := <-srvErr; err == nil {
		err = serr
	}
	return err
}

func newCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key
}

// leaf is a certificate from ca valid for a day before notAfter.
func leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, notAfter time.Time, usage x509.ExtKeyUsage) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "node1"},
		NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
