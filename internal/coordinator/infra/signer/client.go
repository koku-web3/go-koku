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

func (c *Client) SignAcct0(ctx context.Context, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string) (*SignResult, error) {
	return c.signCommon(ctx, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, c.signer.SignAcct0)
}

func (c *Client) SignAcct1(ctx context.Context, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string) (*SignResult, error) {
	return c.signCommon(ctx, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext, c.signer.SignAcct1)
}

func (c *Client) signCommon(ctx context.Context, traceID, chainCode, bip44Path, keyType, message, privKeyCiphertext string, signFn func(context.Context, *signergrpc.SignRequest, ...grpc.CallOption) (*signergrpc.SignResponse, error)) (*SignResult, error) {
	log.Info("Signing request", "trace_id", traceID, "chain_code", chainCode, "bip44_path", bip44Path)

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
	signStart := time.Now()
	resp, err := signFn(ctx, req)
	signCost := time.Since(signStart)
	log.Info("Sign completed", "time_cost_us", signCost.Microseconds(), "success", err == nil)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	return &SignResult{TraceID: traceID, Signature: resp.Signature}, nil
}
