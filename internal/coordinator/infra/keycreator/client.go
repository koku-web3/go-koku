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
	TraceID            string
	Bip32KeyCiphertext string
	Context            string
	Bip44Path          string
	DerivedKeys        []DerivedCoreKeyResult
}

type DerivedCoreKeyResult struct {
	KeyUsage           uint32
	Bip32KeyCiphertext string
	Context            string
	Bip44Path          string
}

type CreateKeyResult struct {
	Keys []DerivedChildKeyResult
}

type DerivedChildKeyResult struct {
	PrivKeyCiphertext string
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
	log.Info("KeyCreatorClient.Genesis",
		"trace_id", traceID,
		"chain_code", chainCode,
		"key_type", keyType)

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
		log.Error("KeyCreatorClient.Genesis failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("keycreator Genesis failed: %w", err)
	}

	derivedKeys := make([]DerivedCoreKeyResult, 0, len(resp.DerivedKeys))
	for _, dk := range resp.DerivedKeys {
		derivedKeys = append(derivedKeys, DerivedCoreKeyResult{
			KeyUsage:           dk.KeyUsage,
			Bip32KeyCiphertext: dk.Bip32KeyCiphertext,
			Context:            dk.Context,
			Bip44Path:          dk.Bip44Path,
		})
	}

	return &GenesisResult{
		TraceID:            traceID,
		Bip32KeyCiphertext: resp.Bip32KeyCiphertext,
		Context:            resp.Context,
		Bip44Path:          resp.Bip44Path,
		DerivedKeys:        derivedKeys,
	}, nil
}

func (c *Client) CreateOperationalKey(ctx context.Context, traceID, chainCode, bip44Path string, accountIndexStart, count uint32, bip32keyCiphertext, keyType string) (*CreateKeyResult, error) {
	return c.createKey(ctx, "Operational", c.keyCreator.CreateOperationalKey, traceID, chainCode, bip44Path, accountIndexStart, count, bip32keyCiphertext, keyType)
}

func (c *Client) CreateUserKey(ctx context.Context, traceID, chainCode, bip44Path string, accountIndexStart, count uint32, bip32keyCiphertext, keyType string) (*CreateKeyResult, error) {
	return c.createKey(ctx, "User", c.keyCreator.CreateUserKey, traceID, chainCode, bip44Path, accountIndexStart, count, bip32keyCiphertext, keyType)
}

type createKeyFunc func(context.Context, *kvgrpc.CreateKeyRequest, ...grpc.CallOption) (*kvgrpc.CreateKeyResponse, error)

func (c *Client) createKey(ctx context.Context, keyType string, fn createKeyFunc, traceID, chainCode, bip44Path string, accountIndexStart, count uint32, bip32keyCiphertext, algoType string) (*CreateKeyResult, error) {
	log.Info(fmt.Sprintf("KeyCreatorClient.Create%sKey", keyType), "trace_id", traceID, "chain_code", chainCode, "bip44Path", bip44Path, "account_index_start", accountIndexStart, "count", count)

	if traceID == "" {
		return nil, fmt.Errorf("trace_id is required")
	}
	if chainCode == "" {
		return nil, fmt.Errorf("chain_code is required")
	}
	if bip32keyCiphertext == "" {
		return nil, fmt.Errorf("bip32key_ciphertext is required")
	}

	resp, err := fn(ctx, &kvgrpc.CreateKeyRequest{
		TraceId:            traceID,
		ChainCode:          chainCode,
		Bip44Path:          bip44Path,
		AccountIndexStart:  accountIndexStart,
		Count:              count,
		Bip32KeyCiphertext: bip32keyCiphertext,
		KeyType:            algoType,
	})
	if err != nil {
		log.Error(fmt.Sprintf("KeyCreatorClient.Create%sKey failed", keyType), "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("keycreator Create%sKey failed: %w", keyType, err)
	}

	return parseCreateKeyResponse(resp), nil
}

func parseCreateKeyResponse(resp *kvgrpc.CreateKeyResponse) *CreateKeyResult {
	keys := make([]DerivedChildKeyResult, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, DerivedChildKeyResult{
			PrivKeyCiphertext: k.PrivKeyCiphertext,
			PublicKey:         k.PublicKey,
			AccountIndex:      k.AddressIndex,
			Context:           k.Context,
			Bip44Path:         k.Bip44Path,
		})
	}
	return &CreateKeyResult{Keys: keys}
}
