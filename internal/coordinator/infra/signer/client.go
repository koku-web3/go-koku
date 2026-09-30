package signer

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	log "github.com/koku-web3/go-koku/pkg/logko"
	signergrpc "github.com/koku-web3/go-koku/pkg/proto/signer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	conn    *grpc.ClientConn
	signer  signergrpc.SignerClient
	address string
}

func NewClient(addr string, tlsCfg *tls.Config) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}

	var opts []grpc.DialOption
	if tlsCfg != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
		log.Info("SignerClient connecting with mTLS", "address", addr)
	} else {
		log.Warn("SignerClient connecting without TLS (insecure)", "address", addr)
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &Client{
		conn:    conn,
		signer:  signergrpc.NewSignerClient(conn),
		address: addr,
	}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Address() string {
	return c.address
}

type SignResult struct {
	TraceID   string
	Signature string
}

func (c *Client) SignAcct0(ctx context.Context, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, dekCiphertext string) (*SignResult, error) {
	return c.sign(ctx, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, dekCiphertext, c.signer.SignAcct0)
}

func (c *Client) SignAcct1(ctx context.Context, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, dekCiphertext string) (*SignResult, error) {
	return c.sign(ctx, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, dekCiphertext, c.signer.SignAcct1)
}

type signFn func(context.Context, *signergrpc.SignRequest, ...grpc.CallOption) (*signergrpc.SignResponse, error)

func (c *Client) sign(ctx context.Context, traceID, chainCode, bip44Path, keyType string, message, privKeyCiphertext, dekCiphertext string, signFunc signFn) (*SignResult, error) {
	req := &signergrpc.SignRequest{
		TraceId:           traceID,
		ChainCode:         chainCode,
		Bip44Path:         bip44Path,
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
		DekCiphertext:     dekCiphertext,
	}
	log.Debug("Calling signer Sign", "trace_id", traceID, "chain_code", chainCode, "bip44_path", bip44Path, "key_type", keyType, "message_length", len(message), "privkey_ciphertext_length", len(privKeyCiphertext), "dek_ciphertext_length", len(dekCiphertext))
	start := time.Now()
	res, err := signFunc(ctx, req)
	cost := time.Since(start)
	if err != nil {
		return nil, err
	}
	log.Info("Call signer Sign succeeded", "trace_id", traceID, "time_cost_ms", cost.Milliseconds(), "signature_length", len(res.Signature))
	return &SignResult{TraceID: traceID, Signature: res.Signature}, nil
}
