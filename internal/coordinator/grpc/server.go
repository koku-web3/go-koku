package grpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/koku-web3/go-koku/internal/coordinator/chain"
	"github.com/koku-web3/go-koku/internal/coordinator/config"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	UnimplementedChainServiceServer
	service *chain.ChainService
	grpcSrv *grpc.Server
	host    string
	port    int
}

func NewServer(service *chain.ChainService, cfg *config.GRPCConfig) *Server {
	return &Server{
		service: service,
		host:    cfg.Host,
		port:    cfg.Port,
	}
}

func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcSrv = grpc.NewServer()
	RegisterChainServiceServer(s.grpcSrv, s)

	reflection.Register(s.grpcSrv)

	log.Info("Starting gRPC server", "address", addr)

	go func() {
		<-ctx.Done()
		log.Info("Shutting down gRPC server")
		s.grpcSrv.GracefulStop()
	}()

	return s.grpcSrv.Serve(lis)
}

func (s *Server) HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	log.Info("gRPC: HealthCheck called")
	return &HealthCheckResponse{
		Status: "ok",
	}, nil
}

func (s *Server) CreateMasterKey(ctx context.Context, req *CreateMasterKeyRequest) (*CreateMasterKeyResponse, error) {
	log.Info("gRPC: CreateMasterKey called", "chain", req.Chain, "name", req.Name, "type", req.Type)

	if req.Chain == "" {
		return nil, fmt.Errorf("chain is required")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("type is required")
	}

	vaultClient := s.service.GetVaultClient()
	if err := vaultClient.CreateMasterKey(req.Chain, req.Name, req.Type, req.Derived); err != nil {
		log.Error("gRPC: Failed to create master key", "error", err)
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	log.Info("gRPC: Master key created successfully", "chain", req.Chain, "name", req.Name)

	result, err := vaultClient.ReadKey(req.Chain, req.Name)
	if err != nil {
		log.Error("gRPC: Failed to read key for public_key", "error", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	var publicKey string
	if result != nil && result.Data != nil {
		if keysMap, ok := result.Data["keys"].(map[string]interface{}); ok {
			for _, v := range keysMap {
				if keyInfo, ok := v.(map[string]interface{}); ok {
					if pk, ok := keyInfo["public_key"].(string); ok {
						publicKey = pk
						break
					}
				}
			}
		}
	}

	return &CreateMasterKeyResponse{
		Message:   fmt.Sprintf("Master key created successfully for chain: %s", req.Chain),
		Chain:     req.Chain,
		Name:      req.Name,
		Type:      req.Type,
		Derived:   req.Derived,
		PublicKey: publicKey,
	}, nil
}

func (s *Server) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	log.Info("gRPC: ListKeys called", "chain", req.Chain)

	if req.Chain == "" {
		return nil, fmt.Errorf("chain is required")
	}

	vaultClient := s.service.GetVaultClient()
	result, err := vaultClient.ListKeys(req.Chain)
	if err != nil {
		log.Error("gRPC: Failed to list keys", "error", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var keys []string
	if result != nil && result.Data != nil {
		if keyList, ok := result.Data["keys"].([]string); ok {
			keys = keyList
		}
	}

	log.Info("gRPC: ListKeys succeeded", "chain", req.Chain, "count", len(keys))
	return &ListKeysResponse{
		Keys: keys,
	}, nil
}

func (s *Server) ReadKey(ctx context.Context, req *ReadKeyRequest) (*ReadKeyResponse, error) {
	log.Info("gRPC: ReadKey called", "chain", req.Chain, "key_name", req.KeyName)

	if req.Chain == "" {
		return nil, fmt.Errorf("chain is required")
	}
	if req.KeyName == "" {
		return nil, fmt.Errorf("key_name is required")
	}

	vaultClient := s.service.GetVaultClient()
	result, err := vaultClient.ReadKey(req.Chain, req.KeyName)
	if err != nil {
		log.Error("gRPC: Failed to read key", "error", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	response := &ReadKeyResponse{}
	if result != nil && result.Data != nil {
		if v, ok := result.Data["request_id"].(string); ok {
			response.RequestId = v
		}
		if v, ok := result.Data["version"].(int); ok {
			response.Version = int64(v)
		}
		if v, ok := result.Data["name"].(string); ok {
			response.Name = v
		}
		if v, ok := result.Data["creation_time"].(string); ok {
			response.CreationTime = v
		}
		if v, ok := result.Data["min_version"].(int); ok {
			response.MinVersion = int64(v)
		}
		if v, ok := result.Data["latest_version"].(int); ok {
			response.LatestVersion = int64(v)
		}
		if keysMap, ok := result.Data["keys"].(map[string]interface{}); ok {
			response.Keys = make(map[string]string)
			for k, v := range keysMap {
				if str, ok := v.(string); ok {
					response.Keys[k] = str
				}
			}
		}
	}

	log.Info("gRPC: ReadKey succeeded", "chain", req.Chain, "key_name", req.KeyName)
	return response, nil
}

func (s *Server) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	log.Info("gRPC: Sign called", "chain", req.Chain, "key_name", req.KeyName)

	if req.Chain == "" {
		return nil, fmt.Errorf("chain is required")
	}
	if req.KeyName == "" {
		return nil, fmt.Errorf("key_name is required")
	}
	if req.Data == "" {
		return nil, fmt.Errorf("data is required")
	}

	data, err := hexDecode(req.Data)
	if err != nil {
		log.Error("gRPC: Invalid hex data", "error", err)
		return nil, fmt.Errorf("invalid hex data: %w", err)
	}

	vaultClient := s.service.GetVaultClient()
	signature, err := vaultClient.Sign(req.Chain, req.KeyName, data)
	if err != nil {
		log.Error("gRPC: Failed to sign", "error", err)
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signatureHex := signatureToHex(signature)

	log.Info("gRPC: Sign succeeded", "chain", req.Chain, "key_name", req.KeyName)
	return &SignResponse{
		Chain:        req.Chain,
		KeyName:      req.KeyName,
		Signature:    signature,
		SignatureHex: signatureHex,
	}, nil
}

func (s *Server) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	log.Info("gRPC: Verify called", "chain", req.Chain, "key_name", req.KeyName)

	if req.Chain == "" {
		return nil, fmt.Errorf("chain is required")
	}
	if req.KeyName == "" {
		return nil, fmt.Errorf("key_name is required")
	}
	if req.Data == "" {
		return nil, fmt.Errorf("data is required")
	}
	if req.Signature == "" {
		return nil, fmt.Errorf("signature is required")
	}

	data, err := hexDecode(req.Data)
	if err != nil {
		log.Error("gRPC: Invalid hex data", "error", err)
		return nil, fmt.Errorf("invalid hex data: %w", err)
	}

	vaultClient := s.service.GetVaultClient()
	valid, err := vaultClient.Verify(req.Chain, req.KeyName, data, req.Signature)
	if err != nil {
		log.Error("gRPC: Failed to verify", "error", err)
		return nil, fmt.Errorf("failed to verify: %w", err)
	}

	log.Info("gRPC: Verify succeeded", "chain", req.Chain, "key_name", req.KeyName, "valid", valid)
	return &VerifyResponse{
		Chain:   req.Chain,
		KeyName: req.KeyName,
		Valid:   valid,
	}, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}

func signatureToHex(signature string) string {
	const prefix = "vault:v1:"
	if len(signature) <= len(prefix) {
		return signature
	}

	b64Data := signature[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return signature
	}

	return hexEncode(decoded)
}

func hexEncode(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return "0x" + string(result)
}
