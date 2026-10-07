package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/key"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/pkg/middleware"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	log "github.com/koku-web3/logko"

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
