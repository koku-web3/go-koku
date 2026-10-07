package grpc

import (
	"context"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/errors"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	log "github.com/koku-web3/logko"
)

func (s *Server) Genesis(ctx context.Context, req *proto.GenesisRequest) (*proto.GenesisResponse, error) {
	if err := validateGenesisRequest(req.TraceId, req.ChainCode); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "genesis", "error", err)
		return nil, errors.InvalidArgumentErr(err)
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

func validateGenesisRequest(traceID, chainCode string) error {
	if traceID == "" {
		return fmt.Errorf("trace_id is required")
	}
	if chainCode == "" || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	return nil
}
