package keycreator

import (
	"context"
	"crypto/tls"
	"fmt"

	log "github.com/koku-web3/go-koku/pkg/logko"
	kvgrpc "github.com/koku-web3/go-koku/pkg/proto/key-creator"

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
	log.Info("KeyCreatorClient.Genesis", "trace_id", traceID, "chain_code", chainCode, "key_type", keyType)

	if traceID == "" {
		return nil, fmt.Errorf("trace_id is required")
	}
	if chainCode == "" {
		return nil, fmt.Errorf("chain_code is required")
	}
	if keyType == "" {
		return nil, fmt.Errorf("key_type is required")
	}

	resp, err := c.keyCreator.Genesis(ctx, &kvgrpc.GenesisRequest{
		TraceId:   traceID,
		ChainCode: chainCode,
		KeyType:   keyType,
	})
	if err != nil {
		log.Error("KeyCreatorClient.Genesis failed", "trace_id", traceID, "error", err.Error())
		return nil, fmt.Errorf("keycreator Genesis failed: %w", err)
	}

	derivedKeys := make([]DerivedCoreKeyResult, 0, len(resp.DerivedKeys))
	for _, dk := range resp.DerivedKeys {
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
		SeedCiphertext: resp.GetSeedCiphertext(),
		DEKCiphertext:  resp.GetDekCiphertext(),
		Context:        resp.GetContext(),
		Bip44Path:      resp.GetBip44Path(),
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
	log.Info(fmt.Sprintf("KeyCreatorClient.Create%sKey", keyType), "trace_id", params.TraceID, "chain_code", params.ChainCode, "bip44_path", params.Bip44Path, "account_index_start", params.AccountIndexStart, "count", params.Count)

	if params.TraceID == "" {
		return nil, fmt.Errorf("trace_id is required")
	}
	if params.ChainCode == "" {
		return nil, fmt.Errorf("chain_code is required")
	}
	if params.Bip32KeyCiphertext == "" {
		return nil, fmt.Errorf("bip32key_ciphertext is required")
	}
	if params.DEKCiphertext == "" {
		return nil, fmt.Errorf("dek_ciphertext is required")
	}

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
	if err != nil {
		log.Error(fmt.Sprintf("Call key-creator server to create %s Key failed", keyType), "trace_id", params.TraceID, "error", err.Error())
		return nil, fmt.Errorf("call key-creator server to Create%sKey failed: %w", keyType, err)
	}

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
