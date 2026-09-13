package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/infra/signer"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/txbuilder"
	"github.com/koku-web3/go-koku/internal/coordinator/model"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	log "github.com/koku-web3/go-koku/pkg/logko"
	tbproto "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
)

type transferServiceImpl struct {
	repo   repository.KeyRepository
	txCli  *txbuilder.Client
	signer *signer.Client
}

func NewTransferService(repo repository.KeyRepository, tx *txbuilder.Client, s *signer.Client) TransferService {
	return &transferServiceImpl{repo: repo, txCli: tx, signer: s}
}

type UniversalTransferInput struct {
	BizID       string
	TraceID     string
	ChainCode   string
	Coin        string
	IsBasicCoin bool
	FromAddress string
	ToAddress   string
	Amount      string
	Contract    string
	KeyUsage    uint8
}

type UniversalTransferResult struct {
	TxID string
}

// verifyAddresses 验证 from 和 to 地址的有效性
func (s *transferServiceImpl) verifyAddresses(ctx context.Context, in *UniversalTransferInput) error {
	verifyR, err := s.txCli.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.FromAddress,
	}, in.ChainCode)
	if err != nil || !verifyR.IsValid {
		return fmt.Errorf("%w: verify from_address failed: %s", ErrNetwork, err)
	}

	verifyToR, err := s.txCli.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.ToAddress,
	}, in.ChainCode)
	if err != nil || !verifyToR.IsValid {
		return fmt.Errorf("%w: verify to_address failed: %s", ErrNetwork, err)
	}

	return nil
}

// verifyContract 验证合约地址（如果适用）
func (s *transferServiceImpl) verifyContract(ctx context.Context, in *UniversalTransferInput) error {
	if !in.IsBasicCoin && in.Contract != "" {
		contractR, err := s.txCli.VerifyContractAddress(ctx, &tbproto.VerifyContractAddressRequest{
			TraceId: in.TraceID,
			Address: in.Contract,
		}, in.ChainCode)
		if err != nil || !contractR.IsValid {
			return fmt.Errorf("%w: verify contract address failed: %s", ErrNetwork, err)
		}
	}
	return nil
}

// checkBalance 验证余额是否充足
func (s *transferServiceImpl) checkBalance(ctx context.Context, in *UniversalTransferInput) error {
	balanceR, err := s.txCli.CheckSufficientBalance(ctx, &tbproto.CheckSufficientBalanceRequest{
		TraceId:     in.TraceID,
		ChainCode:   in.ChainCode,
		Coin:        in.Coin,
		IsBasicCoin: in.IsBasicCoin,
		FromAddress: in.FromAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})
	if err != nil {
		return fmt.Errorf("%w: check sufficient balance failed: %s", ErrNetwork, err)
	}
	if (!in.IsBasicCoin && !balanceR.IsTokenSufficient) || (in.IsBasicCoin && !balanceR.IsCoinSufficient) {
		return fmt.Errorf("%w: insufficient balance", ErrInsufficientBalance)
	}
	return nil
}

// signAndBroadcast 执行签名和广播交易
func (s *transferServiceImpl) signAndBroadcast(ctx context.Context, in *UniversalTransferInput, key *model.ChindKey, rawDataR *tbproto.BuildSignRawDataResponse) (string, error) {
	var sigResult *signer.SignResult
	var err error
	if in.KeyUsage == 0 {
		sigResult, err = s.signer.SignAcct0(ctx, in.TraceID, in.ChainCode, key.BIP44Path, "", rawDataR.Msg, key.Ciphertext)
	} else {
		sigResult, err = s.signer.SignAcct1(ctx, in.TraceID, in.ChainCode, key.BIP44Path, "", rawDataR.Msg, key.Ciphertext)
	}
	if err != nil {
		return "", fmt.Errorf("%w: sign failed: %s", ErrSignFailed, err)
	}

	broadcastR, err := s.txCli.TxBroadcast(ctx, &tbproto.TxBroadcastRequest{
		TraceId:   in.TraceID,
		RawData:   rawDataR.RawData,
		Signature: sigResult.Signature,
	}, in.ChainCode)
	if err != nil {
		return "", fmt.Errorf("%w: broadcast failed: %s", ErrBroadcastFailed, err)
	}
	if !broadcastR.Success {
		return "", fmt.Errorf("%w: broadcast returned failure", ErrBroadcastFailed)
	}

	return in.TraceID, nil
}

func (s *transferServiceImpl) UniversalTransfer(ctx context.Context, in *UniversalTransferInput) (*UniversalTransferResult, error) {
	if err := s.validateInput(in); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParam, err)
	}

	key, err := s.repo.GetKeyByAddress(ctx, in.ChainCode, in.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: get key by address failed: %s", ErrNetwork, err)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: key not found for address %s", ErrKeyNotFound, in.FromAddress)
	}

	if err := s.verifyAddresses(ctx, in); err != nil {
		return nil, err
	}

	if err := s.verifyContract(ctx, in); err != nil {
		return nil, err
	}

	if err := s.checkBalance(ctx, in); err != nil {
		return nil, err
	}

	rawDataR, err := s.txCli.BuildSignRawData(ctx, &tbproto.BuildSignRawDataRequest{
		TraceId:     in.TraceID,
		ChainCode:   in.ChainCode,
		Coin:        in.Coin,
		IsBasicCoin: in.IsBasicCoin,
		CoinSymbol:  in.Coin,
		FromAddress: in.FromAddress,
		ToAddress:   in.ToAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: build sign raw data failed: %s", ErrSignFailed, err)
	}

	txId, err := s.signAndBroadcast(ctx, in, key, rawDataR)
	if err != nil {
		return nil, err
	}

	s.writeAuditLog(ctx, in, key.ID, txId, "SUCCESS")

	return &UniversalTransferResult{TxID: txId}, nil
}

func (s *transferServiceImpl) validateInput(in *UniversalTransferInput) error {
	if in.BizID == "" || len(in.BizID) > 36 {
		return fmt.Errorf("biz_id must be 1-36 characters")
	}
	if in.TraceID == "" || len(in.TraceID) > 36 {
		return fmt.Errorf("trace_id must be 1-36 characters")
	}
	if in.ChainCode == "" || len(in.ChainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if strings.Contains(in.ChainCode, " ") {
		return fmt.Errorf("chain_code cannot contain spaces")
	}
	if in.FromAddress == "" || len(in.FromAddress) > 256 {
		return fmt.Errorf("from_address must be 1-256 characters")
	}
	if in.ToAddress == "" || len(in.ToAddress) > 256 {
		return fmt.Errorf("to_address must be 1-256 characters")
	}
	if in.Amount == "" {
		return fmt.Errorf("amount is required")
	}
	if !in.IsBasicCoin && in.Contract == "" {
		return fmt.Errorf("contract is required when is_basic_coin is false")
	}
	return nil
}

func (s *transferServiceImpl) writeAuditLog(ctx context.Context, in *UniversalTransferInput, keyId uint64, txId, status string) {
	auditLog := &model.AuditLog{
		TraceID:   in.TraceID,
		KeyID:     keyId,
		Operation: "UNIVERSAL_TRANSFER",
		Signature: status,
	}
	if err := s.repo.CreateAuditLog(ctx, auditLog); err != nil {
		log.Error("write audit log failed", "trace_id", in.TraceID, "error", err)
	}
}
