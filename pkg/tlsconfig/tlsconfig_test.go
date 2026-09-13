package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type certBundle struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func (b *certBundle) genCA(t *testing.T) {
	var err error
	b.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &b.caKey.PublicKey, b.caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	b.caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
}

func (b *certBundle) genServerCert(t *testing.T, cn string) ([]byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, b.caCert, key.Public(), b.caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func (b *certBundle) genClientCert(t *testing.T, cn string) ([]byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, b.caCert, key.Public(), b.caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writePEM(t *testing.T, dir, name string, data []byte) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

func TestLoadServerConfig(t *testing.T) {
	dir := t.TempDir()
	var b certBundle
	b.genCA(t)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw})
	caPath := writePEM(t, dir, "ca.pem", caPEM)
	srvCert, srvKey := b.genServerCert(t, "key-creator")
	srvCertPath := writePEM(t, dir, "server.pem", srvCert)
	srvKeyPath := writePEM(t, dir, "server.key", srvKey)

	cfg := ServerConfig{
		CACertFile:     caPath,
		ServerCertFile: srvCertPath,
		ServerKeyFile:  srvKeyPath,
	}
	tlsCfg, err := LoadServerConfig(cfg)
	if err != nil {
		t.Fatalf("LoadServerConfig failed: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected RequireAndVerifyClientCert, got %v", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("expected ClientCAs to be set")
	}
}

func TestLoadClientConfig(t *testing.T) {
	dir := t.TempDir()
	var b certBundle
	b.genCA(t)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw})
	caPath := writePEM(t, dir, "ca.pem", caPEM)
	cliCert, cliKey := b.genClientCert(t, "coordinator-client")
	cliCertPath := writePEM(t, dir, "client.pem", cliCert)
	cliKeyPath := writePEM(t, dir, "client.key", cliKey)

	cfg := ClientConfig{
		CACertFile:     caPath,
		ClientCertFile: cliCertPath,
		ClientKeyFile:  cliKeyPath,
		ServerName:     "key-creator",
	}
	tlsCfg, err := LoadClientConfig(cfg)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be set")
	}
	if tlsCfg.ServerName != "key-creator" {
		t.Fatalf("expected ServerName=key-creator, got %s", tlsCfg.ServerName)
	}
}

func TestNewServerCreds(t *testing.T) {
	dir := t.TempDir()
	var b certBundle
	b.genCA(t)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw})
	caPath := writePEM(t, dir, "ca.pem", caPEM)
	srvCert, srvKey := b.genServerCert(t, "signer")
	writePEM(t, dir, "server.pem", srvCert)
	writePEM(t, dir, "server.key", srvKey)

	creds, err := NewServerCreds(ServerConfig{
		CACertFile:     caPath,
		ServerCertFile: filepath.Join(dir, "server.pem"),
		ServerKeyFile:  filepath.Join(dir, "server.key"),
	})
	if err != nil {
		t.Fatalf("NewServerCreds failed: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}

func TestNewClientCreds(t *testing.T) {
	dir := t.TempDir()
	var b certBundle
	b.genCA(t)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw})
	caPath := writePEM(t, dir, "ca.pem", caPEM)
	cliCert, cliKey := b.genClientCert(t, "coordinator")
	writePEM(t, dir, "client.pem", cliCert)
	writePEM(t, dir, "client.key", cliKey)

	creds, err := NewClientCreds(ClientConfig{
		CACertFile:     caPath,
		ClientCertFile: filepath.Join(dir, "client.pem"),
		ClientKeyFile:  filepath.Join(dir, "client.key"),
		ServerName:     "signer",
	})
	if err != nil {
		t.Fatalf("NewClientCreds failed: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}

func TestLoadServerConfig_MissingFile(t *testing.T) {
	_, err := LoadServerConfig(ServerConfig{
		CACertFile:     "/nonexistent/ca.pem",
		ServerCertFile: "/nonexistent/server.pem",
		ServerKeyFile:  "/nonexistent/server.key",
	})
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

func TestLoadClientConfig_MissingFile(t *testing.T) {
	_, err := LoadClientConfig(ClientConfig{
		CACertFile:     "/nonexistent/ca.pem",
		ClientCertFile: "/nonexistent/client.pem",
		ClientKeyFile:  "/nonexistent/client.key",
		ServerName:     "test",
	})
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

// TestMTLSHandshake 用真实 TCP 连接做端到端 mTLS 握手验证
func TestMTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	var b certBundle
	b.genCA(t)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw})
	caPath := writePEM(t, dir, "ca.pem", caPEM)

	srvCert, srvKey := b.genServerCert(t, "key-creator")
	srvCertPath := writePEM(t, dir, "server.pem", srvCert)
	srvKeyPath := writePEM(t, dir, "server.key", srvKey)

	cliCert, cliKey := b.genClientCert(t, "coordinator")
	cliCertPath := writePEM(t, dir, "client.pem", cliCert)
	cliKeyPath := writePEM(t, dir, "client.key", cliKey)

	srvTLS, err := LoadServerConfig(ServerConfig{
		CACertFile:     caPath,
		ServerCertFile: srvCertPath,
		ServerKeyFile:  srvKeyPath,
	})
	if err != nil {
		t.Fatalf("LoadServerConfig failed: %v", err)
	}

	cliTLS, err := LoadClientConfig(ClientConfig{
		CACertFile:     caPath,
		ClientCertFile: cliCertPath,
		ClientKeyFile:  cliKeyPath,
		ServerName:     "key-creator",
	})
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Logf("failed to close listener: %v", err)
		}
	}()

	const testMsg = "hello-mtls"
	var wg sync.WaitGroup
	var serverErr, clientErr error

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			serverErr = fmt.Errorf("accept failed: %w", err)
			return
		}
		tlsConn := tls.Server(conn, srvTLS)
		defer func() {
			if err := tlsConn.Close(); err != nil {
				serverErr = fmt.Errorf("tls conn close: %w", err)
			}
		}()
		if err := tlsConn.Handshake(); err != nil {
			serverErr = fmt.Errorf("server handshake failed: %w", err)
			return
		}
		buf := make([]byte, 1024)
		n, _ := tlsConn.Read(buf)
		if string(buf[:n]) != testMsg {
			serverErr = fmt.Errorf("expected %q, got %q", testMsg, string(buf[:n]))
			return
		}
		if _, err := tlsConn.Write([]byte("ok")); err != nil {
			serverErr = fmt.Errorf("write failed: %w", err)
			return
		}
	}()

	// Client goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			clientErr = fmt.Errorf("dial failed: %w", err)
			return
		}
		tlsConn := tls.Client(conn, cliTLS)
		defer func() {
			if err := tlsConn.Close(); err != nil {
				clientErr = fmt.Errorf("tls conn close: %w", err)
			}
		}()
		if err := tlsConn.Handshake(); err != nil {
			clientErr = fmt.Errorf("client handshake failed: %w", err)
			return
		}
		if _, err := tlsConn.Write([]byte(testMsg)); err != nil {
			clientErr = fmt.Errorf("write failed: %w", err)
			return
		}
		buf := make([]byte, 1024)
		n, _ := tlsConn.Read(buf)
		if string(buf[:n]) != "ok" {
			clientErr = fmt.Errorf("expected 'ok', got %q", string(buf[:n]))
		}
	}()

	wg.Wait()

	if serverErr != nil {
		t.Errorf("server error: %v", serverErr)
	}
	if clientErr != nil {
		t.Errorf("client error: %v", clientErr)
	}
}
