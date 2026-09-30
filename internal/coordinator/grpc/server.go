package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/key"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/errors"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/middleware"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	proto.UnimplementedCoordinatorServer
	repo    repository.KeyRepository
	keySvc  key.KeyManager
	grpcSrv *grpc.Server
	lis     net.Listener
	host    string
	port    int
	tlsCfg  *tls.Config
}

func NewServer(cfg *config.Config, keySvc key.KeyManager, repo repository.KeyRepository, tlsCfg *tls.Config) *Server {
	return &Server{
		repo:   repo,
		keySvc: keySvc,
		host:   cfg.GRPC.Host,
		port:   cfg.GRPC.Port,
		tlsCfg: tlsCfg,
	}
}

func (s *Server) RunForever(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.lis = lis

	if s.tlsCfg != nil {
		creds := credentials.NewTLS(s.tlsCfg)
		s.grpcSrv = grpc.NewServer(grpc.Creds(creds), middleware.UnaryServerInterceptor())
		log.Info("Starting Coordinator gRPC server with mTLS", "address", addr)
	} else {
		s.grpcSrv = grpc.NewServer(middleware.UnaryServerInterceptor())
		log.Warn("Starting Coordinator gRPC server without TLS (insecure)", "address", addr)
	}
	proto.RegisterCoordinatorServer(s.grpcSrv, s)
	reflection.Register(s.grpcSrv)

	go s.stopOnCancel(ctx)
	return s.grpcSrv.Serve(lis)
}

func (s *Server) stopOnCancel(ctx context.Context) {
	<-ctx.Done()
	log.Info("Shutting down gRPC server")
	s.grpcSrv.GracefulStop()
}

func (s *Server) HealthCheck(ctx context.Context, req *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	return &proto.HealthCheckResponse{Status: "ok"}, nil
}

// ---- validate helpers ----

func validateGenesisRequest(traceID, chainCode string) error {
	if traceID == "" {
		return fmt.Errorf("trace_id is required")
	}
	if chainCode == "" || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	return nil
}

func validateCreateKeyRequest(traceID, chainCode string, count int32) error {
	if traceID == "" {
		return fmt.Errorf("trace_id is required")
	}
	if chainCode == "" || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if count < 1 || count > 50 {
		return fmt.Errorf("count must be 1-50")
	}
	return nil
}

func validateAddressRequest(traceID, chainCode, address string) error {
	if traceID == "" {
		return fmt.Errorf("trace_id is required")
	}
	if chainCode == "" || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if address == "" {
		return fmt.Errorf("address is required")
	}
	return nil
}

func validateBalanceRequest(traceID, chainCode, fromAddress, amount string) error {
	if traceID == "" {
		return fmt.Errorf("trace_id is required")
	}
	if chainCode == "" || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if fromAddress == "" {
		return fmt.Errorf("from_address is required")
	}
	if amount == "" {
		return fmt.Errorf("amount is required")
	}
	return nil
}

// ---- gRPC methods ----

func (s *Server) Genesis(ctx context.Context, req *proto.GenesisRequest) (*proto.GenesisResponse, error) {
	if err := validateGenesisRequest(req.TraceId, req.ChainCode); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "genesis", "error", err)
		return nil, errors.InvalidArgument("genesis request")
	}

	err := s.keySvc.Genesis(ctx, &types.GenesisInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
	})
	if err != nil {
		log.Error("Genesis failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "error", err)
		return nil, errors.Internal()
	}

	log.Info("Genesis succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode)
	return &proto.GenesisResponse{Success: true}, nil
}

func (s *Server) CreateOperationalKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	return s.createKey(ctx, req, keyutil.KEY_USAGE_OPERATIONAL)
}

func (s *Server) CreateUserKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	return s.createKey(ctx, req, keyutil.KEY_USAGE_USER)
}

func (s *Server) createKey(ctx context.Context, req *proto.CreateKeyRequest, usage keyutil.AccountUsage) (*proto.CreateKeyResponse, error) {
	if err := validateCreateKeyRequest(req.TraceId, req.ChainCode, req.Count); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "create_key", "error", err)
		return nil, errors.InvalidArgumentErr(err)
	}

	result, err := s.keySvc.CreateKey(ctx, &types.CreateKeyInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Usage:     usage,
		Count:     req.Count,
	})
	if err != nil {
		log.Error("CreateKey failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "count", req.Count, "usage", usage, "error", err)
		return nil, errors.Internal()
	}

	log.Info("CreateKey succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "usage", usage, "address_count", len(result))
	return &proto.CreateKeyResponse{
		Success:     true,
		AddressList: result,
	}, nil
}

func (s *Server) VerifyAddress(ctx context.Context, req *proto.VerifyAddressRequest) (*proto.VerifyAddressResponse, error) {
	if err := validateAddressRequest(req.TraceId, req.ChainCode, req.Address); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "address", "error", err)
		return nil, errors.InvalidArgument("verify_address")
	}

	valid, err := s.keySvc.VerifyAddress(ctx, &types.VerifyAddressInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Address:   req.Address,
	})
	if err != nil {
		log.Error("VerifyAddress failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "address", req.Address, "error", err)
		return nil, errors.Internal()
	}

	log.Info("VerifyAddress succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "is_valid", valid)
	return &proto.VerifyAddressResponse{IsValid: valid}, nil
}

func (s *Server) VerifyContractAddress(ctx context.Context, req *proto.VerifyContractAddressRequest) (*proto.VerifyContractAddressResponse, error) {
	if err := validateAddressRequest(req.TraceId, req.ChainCode, req.Address); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "contract_address", "error", err)
		return nil, errors.InvalidArgument("verify_contract_address")
	}

	valid, err := s.keySvc.VerifyContractAddress(ctx, &types.VerifyContractAddressInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Address:   req.Address,
	})
	if err != nil {
		log.Error("VerifyContractAddress failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "error", err)
		return nil, errors.Internal()
	}

	log.Info("VerifyContractAddress succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "is_valid", valid)
	return &proto.VerifyContractAddressResponse{IsValid: valid}, nil
}

func (s *Server) CheckSufficientBalance(ctx context.Context, req *proto.CheckSufficientBalanceRequest) (*proto.CheckSufficientBalanceResponse, error) {
	if err := validateBalanceRequest(req.TraceId, req.ChainCode, req.FromAddress, req.Amount); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "balance", "error", err)
		return nil, errors.InvalidArgument("check_balance")
	}

	result, err := s.keySvc.CheckSufficientBalance(ctx, &types.BalanceInput{
		TraceID:     req.TraceId,
		ChainCode:   req.ChainCode,
		Coin:        req.Coin,
		FromAddress: req.FromAddress,
		Amount:      req.Amount,
		Contract:    req.Contract,
	})
	if err != nil {
		log.Error("CheckSufficientBalance failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "coin", req.Coin, "error", err)
		return nil, errors.Internal()
	}

	log.Info("CheckSufficientBalance succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "is_coin_sufficient", result.IsCoinSufficient, "is_token_sufficient", result.IsTokenSufficient)
	return &proto.CheckSufficientBalanceResponse{
		IsCoinSufficient:  result.IsCoinSufficient,
		IsTokenSufficient: result.IsTokenSufficient,
	}, nil
}
