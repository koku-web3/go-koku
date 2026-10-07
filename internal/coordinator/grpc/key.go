package grpc

import (
	"context"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/errors"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	log "github.com/koku-web3/logko"
)

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
