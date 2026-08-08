package grpc

import (
	"context"
	"fmt"
	"net"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	signerclient "github.com/koku-web3/go-koku/internal/coordinator/signer"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server Coordinator gRPC 服务端
// 作为转发层，将请求转发给 Signer 服务
type Server struct {
	UnimplementedChainServiceServer
	client  *signerclient.Client
	grpcSrv *grpc.Server
	host    string
	port    int
}

// NewServer 创建 gRPC 服务端
func NewServer(client *signerclient.Client, cfg *config.GRPCConfig) *Server {
	return &Server{
		client: client,
		host:   cfg.Host,
		port:   cfg.Port,
	}
}

// Start 启动 gRPC 服务
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcSrv = grpc.NewServer()
	RegisterChainServiceServer(s.grpcSrv, s)

	reflection.Register(s.grpcSrv)

	log.Info("Starting Coordinator gRPC server", "address", addr)

	go s.StopWhenCancelled(ctx)

	return s.grpcSrv.Serve(lis)
}

// Shutdown 优雅关闭：先关闭 client，再停止 gRPC server
func (s *Server) StopWhenCancelled(ctx context.Context) {
	<-ctx.Done()

	log.Info("Closing signer client")
	if err := s.client.Close(); err != nil {
		log.Error(fmt.Sprintf("close signer client failed: %v", err))
	}

	log.Info("Shutting down gRPC server")
	s.grpcSrv.GracefulStop()
}

// HealthCheck 健康检查
func (s *Server) HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{
		Status: "ok",
	}, nil
}

// CreateMasterKey 创建主密钥
func (s *Server) CreateMasterKey(ctx context.Context, req *CreateMasterKeyRequest) (*CreateMasterKeyResponse, error) {
	log.Info("CreateMasterKey", "trace_id", req.TraceId, "chain", req.Chain, "key_type", req.KeyType)

	result, err := s.client.CreateMasterKey(ctx, req.TraceId, req.Chain, req.KeyType)
	if err != nil {
		log.Error("CreateMasterKey failed", "error", err)
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	return &CreateMasterKeyResponse{
		TraceId:        result.TraceID,
		KeyName:        result.KeyName,
		SeedCiphertext: result.SeedCiphertext,
		PublicKey:      result.PublicKey,
		Bip44Path:      result.BIP44Path,
	}, nil
}

// CreateDerivedKey 创建派生密钥
func (s *Server) CreateDerivedKey(ctx context.Context, req *CreateDerivedKeyRequest) (*CreateDerivedKeyResponse, error) {
	log.Info("CreateDerivedKey", "trace_id", req.TraceId, "chain", req.Chain, "master_key_name", req.MasterKeyName)

	result, err := s.client.CreateDerivedKey(ctx, req.TraceId, req.Chain, req.MasterKeyName, req.MasterKeyPemCiphertext, int32(req.KeyUsage), req.KeyType, req.AddressIndex)
	if err != nil {
		log.Error("CreateDerivedKey failed", "error", err)
		return nil, fmt.Errorf("failed to create derived key: %w", err)
	}

	return &CreateDerivedKeyResponse{
		TraceId:           result.TraceID,
		KeyName:           result.KeyName,
		PrivKeyCiphertext: result.PrivKeyCiphertext,
		PublicKey:         result.PublicKey,
		Bip44Path:         result.BIP44Path,
		KeyContext:        result.KeyContext,
	}, nil
}

// Sign 签名消息
func (s *Server) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	log.Info("Sign", "trace_id", req.TraceId, "chain", req.Chain, "key_name", req.KeyName)

	result, err := s.client.Sign(ctx, req.TraceId, req.Chain, req.KeyName, int32(req.KeyUsage), req.KeyType, req.KeyContext, req.Message, req.PrivKeyCiphertext)
	if err != nil {
		log.Error("Sign failed", "error", err)
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &SignResponse{
		TraceId:   result.TraceID,
		Signature: result.Signature,
	}, nil
}
