package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/infra/signer"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/txbuilder"
	"github.com/koku-web3/go-koku/internal/coordinator/model"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/internal/coordinator/tx"
	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	log "github.com/koku-web3/go-koku/pkg/logko"
	tbproto "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
)

type transferService struct {
	repo   repository.KeyRepository
	txCli  *txbuilder.Client
	signer *signer.Client
}

func NewTransferService(repo repository.KeyRepository, tx *txbuilder.Client, s *signer.Client) tx.TransferManager {
	return &transferService{repo: repo, txCli: tx, signer: s}
}

// verifyAddresses 验证 from 和 to 地址的有效性
func (s *transferService) verifyAddresses(ctx context.Context, in *types.UniversalTransferInput) error {
	verifyR, err := s.txCli.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.FromAddress,
	}, in.ChainCode)
	if err != nil || !verifyR.IsValid {
		return fmt.Errorf("%w: verify from_address failed: %s", tx.ErrNetwork, err)
	}

	verifyToR, err := s.txCli.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.ToAddress,
	}, in.ChainCode)
	if err != nil || !verifyToR.IsValid {
		return fmt.Errorf("%w: verify to_address failed: %s", tx.ErrNetwork, err)
	}

	return nil
}

// verifyContract 验证合约地址
func (s *transferService) verifyContract(ctx context.Context, in *types.UniversalTransferInput) error {
	if in.Contract != "" {
		contractR, err := s.txCli.VerifyContractAddress(ctx, &tbproto.VerifyContractAddressRequest{
			TraceId: in.TraceID,
			Address: in.Contract,
		}, in.ChainCode)
		if err != nil || !contractR.IsValid {
			return fmt.Errorf("%w: verify contract address failed: %s", tx.ErrNetwork, err)
		}
	}
	return nil
}

// checkBalance 验证余额是否充足
func (s *transferService) checkBalance(ctx context.Context, in *types.UniversalTransferInput) error {
	res, err := s.txCli.CheckSufficientBalance(ctx, &tbproto.CheckSufficientBalanceRequest{
		TraceId:     in.TraceID,
		ChainCode:   in.ChainCode,
		Coin:        in.Coin,
		FromAddress: in.FromAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})
	if err != nil {
		return fmt.Errorf("%w: check sufficient balance failed: %s", tx.ErrNetwork, err)
	}

	var msgs []string
	if in.IsContractTx() {
		if !res.IsCoinSufficient {
			msgs = append(msgs, "insufficient fee")
		}
		if !res.IsTokenSufficient {
			msgs = append(msgs, "insufficient token balance")
		}
	} else {
		if !res.IsCoinSufficient {
			msgs = append(msgs, "insufficient base coin balance")
		}
	}

	if len(msgs) == 0 {
		return nil
	}

	log.Warn("Insufficient balance detected", "trace_id", in.TraceID, "chain_code", in.ChainCode, "coin", in.Coin, "from_address", in.FromAddress, "amount", in.Amount, "contract", in.Contract, "coin_sufficient", res.IsCoinSufficient, "token_sufficient", res.IsTokenSufficient)

	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// signAndBroadcast 执行签名和广播交易
func (s *transferService) signAndBroadcast(ctx context.Context, in *types.UniversalTransferInput, keyType string, key *model.ChindKey, rawDataR *tbproto.BuildSignRawDataResponse) (string, error) {
	var sigResult *signer.SignResult
	var err error
	if keyutil.KEY_USAGE_OPERATIONAL.ToUin32() == in.KeyUsage {
		sigResult, err = s.signer.SignAcct0(ctx, in.TraceID, in.ChainCode, key.BIP44Path, keyType, rawDataR.Msg, key.Ciphertext)
	} else {
		sigResult, err = s.signer.SignAcct1(ctx, in.TraceID, in.ChainCode, key.BIP44Path, keyType, rawDataR.Msg, key.Ciphertext)
	}
	if err != nil {
		return "", fmt.Errorf("%w: sign failed: %s", tx.ErrSignFailed, err)
	}

	broadcastR, err := s.txCli.TxBroadcast(ctx, &tbproto.TxBroadcastRequest{
		TraceId:   in.TraceID,
		RawData:   rawDataR.RawData,
		Signature: sigResult.Signature,
	}, in.ChainCode)
	if err != nil {
		return "", fmt.Errorf("%w: broadcast failed: %s", tx.ErrBroadcastFailed, err)
	}
	if !broadcastR.Success {
		return "", fmt.Errorf("%w: broadcast returned failure", tx.ErrBroadcastFailed)
	}

	return broadcastR.TxHash, nil
}

func (s *transferService) UniversalTransfer(ctx context.Context, in *types.UniversalTransferInput) (*types.UniversalTransferResult, error) {
	if err := s.validateInput(in); err != nil {
		return nil, fmt.Errorf("%w: %s", tx.ErrInvalidParam, err)
	}

	mk, err := s.repo.GetMasterKeyByChainCode(ctx, in.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("%w: get master key by chain code failed: %s", tx.ErrNetwork, err)
	}

	key, err := s.repo.GetKeyByAddress(ctx, in.ChainCode, in.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: get key by address failed: %s", tx.ErrNetwork, err)
	}
	if key == nil {
		return nil, fmt.Errorf("%w: key not found for address %s", tx.ErrKeyNotFound, in.FromAddress)
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
		CoinSymbol:  in.Coin,
		FromAddress: in.FromAddress,
		ToAddress:   in.ToAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})

	if err != nil {
		return nil, err
	}

	txHash, err := s.signAndBroadcast(ctx, in, mk.KeyType, key, rawDataR)
	if err != nil {
		return nil, err
	}

	s.writeAuditLog(ctx, in, key.ID, txHash, "SUCCESS")

	return &types.UniversalTransferResult{TxHash: txHash}, nil
}

func (s *transferService) validateInput(in *types.UniversalTransferInput) error {
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
	return nil
}

func (s *transferService) writeAuditLog(ctx context.Context, in *types.UniversalTransferInput, keyId uint64, txId, status string) {
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
