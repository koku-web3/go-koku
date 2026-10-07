package grpc

import (
	"context"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/errors"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	log "github.com/koku-web3/logko"
)

func (s *Server) VerifyAddress(ctx context.Context, req *proto.VerifyAddressRequest) (*proto.VerifyAddressResponse, error) {
	if err := validateAddressRequest(req.TraceId, req.ChainCode, req.Address); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "error", err)
		return nil, errors.InvalidArgumentErr(err)
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
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "error", err)
		return nil, errors.InvalidArgumentErr(err)
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
