package grpc

import (
	"context"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/errors"
	proto "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	log "github.com/koku-web3/logko"
)

func (s *Server) CheckSufficientBalance(ctx context.Context, req *proto.CheckSufficientBalanceRequest) (*proto.CheckSufficientBalanceResponse, error) {
	if err := validateBalanceRequest(req.TraceId, req.ChainCode, req.FromAddress, req.Amount); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "balance", "error", err)
		return nil, errors.InvalidArgumentErr(err)
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
