package mq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/koku-web3/go-koku/internal/coordinator/key"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/internal/coordinator/tx"
	"github.com/koku-web3/go-koku/internal/coordinator/types"
	log "github.com/koku-web3/go-koku/pkg/logko"
)

type Handler struct {
	transfer tx.TransferManager
	repo     repository.KeyRepository
}

func NewHandler(transferMgr tx.TransferManager, repo repository.KeyRepository) *Handler {
	return &Handler{transfer: transferMgr, repo: repo}
}

type UniversalTransferMsg struct {
	BizID       string `json:"biz_id"`
	TraceID     string `json:"trace_id"`
	ChainCode   string `json:"chain_code"`
	Coin        string `json:"coin"`
	IsBasicCoin bool   `json:"is_basic_coin"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Amount      string `json:"amount"`
	Contract    string `json:"contract"`
}

func ParseMsg(body []byte) (*UniversalTransferMsg, error) {
	var msg UniversalTransferMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}
	return &msg, nil
}

// RoutingKeyFor is defined in router.go

func (h *Handler) Handle(ctx context.Context, routingKey string, msg *UniversalTransferMsg) error {
	log.Info("MQ UniversalTransfer received",
		"trace_id", msg.TraceID, "biz_id", msg.BizID, "chain_code", msg.ChainCode,
		"from_address", msg.FromAddress, "to_address", msg.ToAddress,
		"amount", msg.Amount, "routing_key", routingKey)

	keyUsage, err := RoutingKeyFor(routingKey)
	if err != nil {
		return NewPermanentErrorFromError(err)
	}

	result, err := h.transfer.UniversalTransfer(ctx, &types.UniversalTransferInput{
		BizID:       msg.BizID,
		TraceID:     msg.TraceID,
		ChainCode:   msg.ChainCode,
		Coin:        msg.Coin,
		FromAddress: msg.FromAddress,
		ToAddress:   msg.ToAddress,
		Amount:      msg.Amount,
		Contract:    msg.Contract,
		KeyUsage:    keyUsage,
	})

	if err == nil {
		log.Info("UniversalTransferCallback", "success", true, "biz_id", msg.BizID, "tract_id", msg.TraceID, "tx_hash", result.TxHash)
		return nil
	} else {
		log.Info("UniversalTransferCallback", "success", false, "biz_id", msg.BizID, "tract_id", msg.TraceID, "error", err.Error())
	}

	if errors.Is(err, key.ErrInvalidParam) ||
		errors.Is(err, key.ErrKeyNotFound) ||
		errors.Is(err, key.ErrInsufficientBalance) ||
		errors.Is(err, key.ErrGenesisExists) {
		return NewPermanentErrorFromError(err)
	}

	return NewTransientErrorFromError(err)
}
