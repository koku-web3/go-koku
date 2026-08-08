package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn    *grpc.ClientConn
	service ChainServiceClient
}

func NewClient(addr string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	conn.Connect()

	return &Client{
		conn:    conn,
		service: NewChainServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) (*HealthCheckResponse, error) {
	return c.service.HealthCheck(ctx, &HealthCheckRequest{})
}

func (c *Client) CreateMasterKey(ctx context.Context, chain, name, keyType string, derived bool) (*CreateMasterKeyResponse, error) {
	return c.service.CreateMasterKey(ctx, &CreateMasterKeyRequest{
		Chain:   chain,
		Name:    name,
		Type:    keyType,
		Derived: derived,
	})
}

func (c *Client) ListKeys(ctx context.Context, chain string) (*ListKeysResponse, error) {
	return c.service.ListKeys(ctx, &ListKeysRequest{
		Chain: chain,
	})
}

func (c *Client) ReadKey(ctx context.Context, chain, keyName string) (*ReadKeyResponse, error) {
	return c.service.ReadKey(ctx, &ReadKeyRequest{
		Chain:   chain,
		KeyName: keyName,
	})
}

func (c *Client) Sign(ctx context.Context, chain, keyName, data string) (*SignResponse, error) {
	return c.service.Sign(ctx, &SignRequest{
		Chain:   chain,
		KeyName: keyName,
		Data:    data,
	})
}

func (c *Client) Verify(ctx context.Context, chain, keyName, data, signature string) (*VerifyResponse, error) {
	return c.service.Verify(ctx, &VerifyRequest{
		Chain:     chain,
		KeyName:   keyName,
		Data:      data,
		Signature: signature,
	})
}
