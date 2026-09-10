package signer

import (
	"context"
	"crypto/tls"
	"fmt"

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

func (c *Client) Sign(
	ctx context.Context,
	traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string,
) (*SignResult, error) {
	log.Info("Sign", "trace_id", traceID, "chain_code", chainCode)

	if bip44Path == "" {
		return nil, fmt.Errorf("bip44_path is required")
	}
	if privKeyCiphertext == "" {
		return nil, fmt.Errorf("priv_key_ciphertext is required")
	}

	req := &signergrpc.SignRequest{
		TraceId:           traceID,
		ChainCode:         chainCode,
		Bip44Path:         bip44Path,
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
	}

	resp, err := c.signer.SignAcct0(ctx, req)
	if err != nil {
		log.Error("Sign failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer SignAcct0 failed: %w", err)
	}

	return &SignResult{
		TraceID:   traceID,
		Signature: resp.Signature,
	}, nil
}

func (c *Client) SignAcct0(
	ctx context.Context,
	traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string,
) (*SignResult, error) {
	log.Info("SignAcct0", "trace_id", traceID, "chain_code", chainCode, "bip44_path", bip44Path)

	if bip44Path == "" {
		return nil, fmt.Errorf("bip44_path is required")
	}
	if privKeyCiphertext == "" {
		return nil, fmt.Errorf("priv_key_ciphertext is required")
	}

	req := &signergrpc.SignRequest{
		TraceId:           traceID,
		ChainCode:         chainCode,
		Bip44Path:         bip44Path,
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
	}

	resp, err := c.signer.SignAcct0(ctx, req)
	if err != nil {
		log.Error("SignAcct0 failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer SignAcct0 failed: %w", err)
	}

	return &SignResult{TraceID: traceID, Signature: resp.Signature}, nil
}

func (c *Client) SignAcct1(
	ctx context.Context,
	traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string,
) (*SignResult, error) {
	log.Info("SignAcct1", "trace_id", traceID, "chain_code", chainCode, "bip44_path", bip44Path)

	if bip44Path == "" {
		return nil, fmt.Errorf("bip44_path is required")
	}
	if privKeyCiphertext == "" {
		return nil, fmt.Errorf("priv_key_ciphertext is required")
	}

	req := &signergrpc.SignRequest{
		TraceId:           traceID,
		ChainCode:         chainCode,
		Bip44Path:         bip44Path,
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
	}

	resp, err := c.signer.SignAcct1(ctx, req)
	if err != nil {
		log.Error("SignAcct1 failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer SignAcct1 failed: %w", err)
	}

	return &SignResult{TraceID: traceID, Signature: resp.Signature}, nil
}
