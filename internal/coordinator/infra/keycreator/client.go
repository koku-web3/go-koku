package keycreator

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	kvgrpc "github.com/koku-web3/go-koku/pkg/proto/key-creator"
	log "github.com/koku-web3/logko"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	conn       *grpc.ClientConn
	keyCreator kvgrpc.KeyCreatorClient
	address    string
}

type GenesisResult struct {
	TraceID        string
	SeedCiphertext string
	DEKCiphertext  string // 加解密 Bip32KeyCiphertext 的密钥
	Context        string
	Bip44Path      string
	DerivedKeys    []DerivedCoreKeyResult
}

type DerivedCoreKeyResult struct {
	KeyUsage           uint32
	Bip32KeyCiphertext string
	DEKCiphertext      string // 加解密 Bip32KeyCiphertext 的密钥
	Context            string
	Bip44Path          string
}

type CreateKeyResult struct {
	Keys []DerivedChildKeyResult
}

type DerivedChildKeyResult struct {
	PrivKeyCiphertext string
	DEKCiphertext     string // 加解密 Bip32KeyCiphertext 的密钥
	PublicKey         string
	AccountIndex      uint32
	Context           string
	Bip44Path         string
}

func NewClient(addr string, tlsCfg *tls.Config) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}

	var opts []grpc.DialOption
	if tlsCfg != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
		log.Info("KeyCreatorClient connecting with mTLS", "address", addr)
	} else {
		log.Warn("KeyCreatorClient connecting without TLS (insecure)", "address", addr)
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &Client{
		conn:       conn,
		keyCreator: kvgrpc.NewKeyCreatorClient(conn),
		address:    addr,
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

func (c *Client) Genesis(ctx context.Context, traceID, chainCode, keyType string) (*GenesisResult, error) {
	if keyType == "" {
		return nil, fmt.Errorf("key_type is required")
	}

	start := time.Now()
	log.Debug("Calling key-creator Genesis", "trace_id", traceID, "chain_code", chainCode, "key_type", keyType)
	res, err := c.keyCreator.Genesis(ctx, &kvgrpc.GenesisRequest{
		TraceId:   traceID,
		ChainCode: chainCode,
		KeyType:   keyType,
	})
	cost := time.Since(start)
	if err != nil {
		return nil, err
	}

	log.Info("Call key-creator Genesis succeeded", "trace_id", traceID, "seed_ciphertext_length", len(res.SeedCiphertext), "dek_ciphertext_length", len(res.DekCiphertext), "derived_count", len(res.DerivedKeys), "time_cost_ms", cost.Milliseconds())
	derivedKeys := make([]DerivedCoreKeyResult, 0, len(res.DerivedKeys))
	for _, dk := range res.DerivedKeys {
		derivedKeys = append(derivedKeys, DerivedCoreKeyResult{
			KeyUsage:           dk.KeyUsage,
			Bip32KeyCiphertext: dk.Bip32KeyCiphertext,
			DEKCiphertext:      dk.DekCiphertext,
			Context:            dk.Context,
			Bip44Path:          dk.Bip44Path,
		})
	}

	return &GenesisResult{
		TraceID:        traceID,
		SeedCiphertext: res.GetSeedCiphertext(),
		DEKCiphertext:  res.GetDekCiphertext(),
		Context:        res.GetContext(),
		Bip44Path:      res.GetBip44Path(),
		DerivedKeys:    derivedKeys,
	}, nil
}

type CreateKeyParams struct {
	TraceID            string
	ChainCode          string
	Bip44Path          string
	AccountIndexStart  uint32
	Count              uint32
	Bip32KeyCiphertext string
	DEKCiphertext      string
	AlgoType           string
}

type createKeyFunc func(context.Context, *kvgrpc.CreateKeyRequest, ...grpc.CallOption) (*kvgrpc.CreateKeyResponse, error)

func (c *Client) CreateOperationalKey(ctx context.Context, params CreateKeyParams) (*CreateKeyResult, error) {
	return c.createKey(ctx, "Operational", c.keyCreator.CreateOperationalKey, params)
}

func (c *Client) CreateUserKey(ctx context.Context, params CreateKeyParams) (*CreateKeyResult, error) {
	return c.createKey(ctx, "User", c.keyCreator.CreateUserKey, params)
}

func (c *Client) createKey(ctx context.Context, keyType string, fn createKeyFunc, params CreateKeyParams) (*CreateKeyResult, error) {
	log.Debug("Calling key-creator CreateKey", "trace_id", params.TraceID, "key_type", keyType, "chain_code", params.ChainCode, "bip44_path", params.Bip44Path, "account_index_start", params.AccountIndexStart, "count", params.Count)
	start := time.Now()
	resp, err := fn(ctx, &kvgrpc.CreateKeyRequest{
		TraceId:            params.TraceID,
		ChainCode:          params.ChainCode,
		Bip44Path:          params.Bip44Path,
		AccountIndexStart:  params.AccountIndexStart,
		Count:              params.Count,
		Bip32KeyCiphertext: params.Bip32KeyCiphertext,
		DekCiphertext:      params.DEKCiphertext,
		KeyType:            params.AlgoType,
	})
	cost := time.Since(start)
	if err != nil {
		return nil, err
	}
	log.Info("Call key-creator CreateKey succeeded", "trace_id", params.TraceID, "key_type", keyType, "key_count", len(resp.Keys), "time_cost_ms", cost.Milliseconds())

	return parseCreateKeyResponse(resp), nil
}

func parseCreateKeyResponse(resp *kvgrpc.CreateKeyResponse) *CreateKeyResult {
	keys := make([]DerivedChildKeyResult, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, DerivedChildKeyResult{
			PrivKeyCiphertext: k.PrivKeyCiphertext,
			DEKCiphertext:     k.DekCiphertext,
			PublicKey:         k.PublicKey,
			AccountIndex:      k.AddressIndex,
			Context:           k.Context,
			Bip44Path:         k.Bip44Path,
		})
	}
	return &CreateKeyResult{Keys: keys}
}
