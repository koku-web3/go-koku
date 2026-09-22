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
	"github.com/koku-web3/go-koku/pkg/keyutil"
	log "github.com/koku-web3/go-koku/pkg/logko"
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

	if s.tlsCfg != nil {
		creds := credentials.NewTLS(s.tlsCfg)
		s.grpcSrv = grpc.NewServer(grpc.Creds(creds))
		log.Info("Starting Coordinator gRPC server with mTLS", "address", addr)
	} else {
		s.grpcSrv = grpc.NewServer()
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

func (s *Server) Genesis(ctx context.Context, req *proto.GenesisRequest) (*proto.GenesisResponse, error) {
	log.Info("Genesis", "trace_id", req.TraceId, "chain_code", req.ChainCode, "key_type", req.KeyType)

	err := s.keySvc.Genesis(ctx, &types.GenesisInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		KeyType:   req.KeyType,
	})

	log.Debug("Genesis completed", "success", err == nil)
	return &proto.GenesisResponse{Success: err == nil}, err
}

func (s *Server) CreateOperationalKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	log.Info("CreateOperationalKey ready", "trace_id", req.TraceId, "chain_code", req.ChainCode, "count", req.Count)

	log.Debug("CreateOperationalKey -> CreateKey", "trace_id", req.TraceId)

	result, err := s.keySvc.CreateKey(ctx, &types.CreateKeyInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Usage:     keyutil.KEY_USAGE_OPERATIONAL,
		Count:     req.Count,
	})
	if err != nil {
		log.Error("CreateOperationalKey failed", "trace_id", req.TraceId, "error", err.Error())
	} else {
		log.Debug("CreateOperationalKey success", "trace_id", req.TraceId)
		log.Debug("CreateOperationalKey response", "trace_id", req.TraceId, "address_list", result)
	}

	return &proto.CreateKeyResponse{
		Success:     err == nil,
		AddressList: result,
	}, err
}

func (s *Server) CreateUserKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	log.Info("CreateUserKey", "trace_id", req.TraceId, "chain_code", req.ChainCode, "count", req.Count)

	result, err := s.keySvc.CreateKey(ctx, &types.CreateKeyInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Usage:     keyutil.KEY_USAGE_USER,
		Count:     req.Count,
	})

	log.Debug("CreateUserKey completed", "trace_id", req.TraceId, "success", err == nil)
	return &proto.CreateKeyResponse{
		Success:     err == nil,
		AddressList: result,
	}, err
}

func (s *Server) VerifyAddress(ctx context.Context, req *proto.VerifyAddressRequest) (*proto.VerifyAddressResponse, error) {
	log.Info("VerifyAddress", "trace_id", req.TraceId, "chain_code", req.ChainCode, "address", req.Address)

	valid, err := s.keySvc.VerifyAddress(ctx, &types.VerifyAddressInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Address:   req.Address,
	})
	if err != nil {
		return nil, err
	}

	log.Debug("VerifyAddress completed", "is_valid", valid)
	return &proto.VerifyAddressResponse{IsValid: valid}, nil
}

func (s *Server) VerifyContractAddress(ctx context.Context, req *proto.VerifyContractAddressRequest) (*proto.VerifyContractAddressResponse, error) {
	log.Info("VerifyContractAddress", "trace_id", req.TraceId, "chain_code", req.ChainCode, "address", req.Address)

	valid, err := s.keySvc.VerifyContractAddress(ctx, &types.VerifyContractAddressInput{
		TraceID:   req.TraceId,
		ChainCode: req.ChainCode,
		Address:   req.Address,
	})
	if err != nil {
		return nil, err
	}

	log.Debug("VerifyContractAddress completed", "is_valid", valid)
	return &proto.VerifyContractAddressResponse{IsValid: valid}, nil
}

func (s *Server) CheckSufficientBalance(ctx context.Context, req *proto.CheckSufficientBalanceRequest) (*proto.CheckSufficientBalanceResponse, error) {
	log.Info("CheckSufficientBalance", "trace_id", req.TraceId, "chain_code", req.ChainCode, "coin", req.Coin, "is_base_coin", req.IsBasicCoin, "from", req.FromAddress, "amount", req.Amount, "contract", req.Contract)

	result, err := s.keySvc.CheckSufficientBalance(ctx, &types.BalanceInput{
		TraceID:     req.TraceId,
		ChainCode:   req.ChainCode,
		Coin:        req.Coin,
		IsBasicCoin: req.IsBasicCoin,
		FromAddress: req.FromAddress,
		Amount:      req.Amount,
		Contract:    req.Contract,
	})
	if err != nil {
		return nil, err
	}

	log.Debug("CheckSufficientBalance completed", "is_coin_sufficient", result.IsCoinSufficient, "is_token_sufficient", result.IsTokenSufficient)
	return &proto.CheckSufficientBalanceResponse{
		IsCoinSufficient:  result.IsCoinSufficient,
		IsTokenSufficient: result.IsTokenSufficient,
	}, nil
}
