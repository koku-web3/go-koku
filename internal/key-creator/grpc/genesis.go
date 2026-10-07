package grpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/pkg/errors"
	proto "github.com/koku-web3/go-koku/pkg/proto/key-creator"
	"github.com/koku-web3/go-koku/pkg/securestore/algorithm"
	log "github.com/koku-web3/logko"
)

func (s *KeyCreatorService) Genesis(ctx context.Context, req *proto.GenesisRequest) (*proto.GenesisResponse, error) {
	if err := validateGenesisRequest(req); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "error", err)
		// err 只有字面量字符串，不包含任何敏感信息，可以直接返回给调用方
		return nil, errors.InvalidArgumentErr(err)
	}

	res, err := s.generateThreeCoreKeys(req.ChainCode)
	if err != nil {
		log.Error("Genesis failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "error", err)
		return nil, errors.Internal()
	}

	log.Info("Genesis succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "derived_count", len(res.DerivedKeys))
	return res, nil
}

// validateGenesisRequest 校验 Genesis 请求参数
func validateGenesisRequest(req *proto.GenesisRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 32 {
		errors = append(errors, "chain_code must be 1-32 characters")
	}
	if req.KeyType == "" || len(req.KeyType) > 32 {
		errors = append(errors, "key_type must be 1-32 characters")
	}
	// 验证 keyType 是否支持
	if !algorithm.IsSupported(req.KeyType) {
		errors = append(errors, "unsupported key type")
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}
