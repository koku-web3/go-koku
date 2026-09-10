package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/infra/keycreator"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/txbuilder"
	"github.com/koku-web3/go-koku/internal/coordinator/model"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	coordinator "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	tbproto "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
)

type keyServiceImpl struct {
	repo     repository.KeyRepository
	kcClient *keycreator.Client
	txClient *txbuilder.Client
}

func NewKeyService(repo repository.KeyRepository, kc *keycreator.Client, tx *txbuilder.Client) KeyService {
	return &keyServiceImpl{repo: repo, kcClient: kc, txClient: tx}
}

type GenesisInput struct {
	TraceID   string
	ChainCode string
	KeyType   string
}

func (s *keyServiceImpl) Genesis(ctx context.Context, in *GenesisInput) error {
	if err := validateTraceId(in.TraceID); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidParam, err)
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidParam, err)
	}

	existing, err := s.repo.GetMasterKeyByChainCode(ctx, in.ChainCode)
	if err != nil {
		return fmt.Errorf("%w: failed to check master key: %s", ErrNetwork, err)
	}
	if existing != nil {
		return fmt.Errorf("%w: master keys already exist for chain %s", ErrGenesisExists, in.ChainCode)
	}

	count, err := s.repo.GetCoreKeyCountByChainCode(ctx, in.ChainCode)
	if err != nil {
		return fmt.Errorf("%w: failed to check core keys: %s", ErrNetwork, err)
	}
	if count > 0 {
		return fmt.Errorf("%w: core keys already exist for chain %s", ErrGenesisExists, in.ChainCode)
	}

	result, err := s.kcClient.Genesis(ctx, in.TraceID, in.ChainCode, in.KeyType)
	if err != nil {
		return fmt.Errorf("%w: key creator genesis failed: %s", ErrNetwork, err)
	}

	masterKey := &model.MasterKey{
		ChainCode:          in.ChainCode,
		KeyType:            in.KeyType,
		Bip32KeyCiphertext: result.Bip32KeyCiphertext,
		Context:            result.Context,
		Bip44Path:          result.Bip44Path,
		IsDeleted:          false,
	}

	coreKeys := make([]*model.CoreKey, 0, len(result.DerivedKeys))
	for _, dk := range result.DerivedKeys {
		coreKeys = append(coreKeys, &model.CoreKey{
			ChainCode:          in.ChainCode,
			KeyUsage:           uint8(dk.KeyUsage),
			Bip32KeyCiphertext: dk.Bip32KeyCiphertext,
			Context:            dk.Context,
			Bip44Path:          dk.Bip44Path,
			IsDeleted:          false,
		})
	}

	if err := s.repo.InsertGenesisRecordsAtomic(ctx, masterKey, coreKeys); err != nil {
		return fmt.Errorf("%w: failed to save genesis records: %s", ErrNetwork, err)
	}

	return nil
}

type CreateKeyInput struct {
	TraceID   string
	ChainCode string
	Usage     keyutil.AccountUsage
	Count     int32
}

func (s *keyServiceImpl) CreateKey(ctx context.Context, in *CreateKeyInput) ([]*coordinator.AddressInfo, error) {
	if err := validateTraceId(in.TraceID); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParam, err)
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParam, err)
	}
	if in.Count < 1 || in.Count > 50 {
		return nil, fmt.Errorf("%w: count must be 1-50", ErrInvalidParam)
	}

	maxIndex, err := s.repo.GetMaxAccountIndex(ctx, in.ChainCode, in.Usage.ToUin32())
	if err != nil {
		return nil, fmt.Errorf("%w: GetMaxAccountIndex failed: %s", ErrNetwork, err)
	}
	accountIndexStart := maxIndex + 1

	coreKey, err := s.repo.GetCoreKeyByChainCodeAndUsage(ctx, in.ChainCode, in.Usage.ToUin32())
	if err != nil {
		return nil, fmt.Errorf("%w: GetCoreKeyByChainCodeAndUsage failed: %s", ErrNetwork, err)
	}
	if coreKey == nil {
		return nil, fmt.Errorf("%w: core key not found, run genesis first", ErrKeyNotFound)
	}

	masterKey, err := s.repo.GetMasterKeyByChainCode(ctx, in.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("%w: GetMasterKeyByChainCode failed: %s", ErrNetwork, err)
	}
	if masterKey == nil {
		return nil, fmt.Errorf("%w: master key not found, run genesis first", ErrKeyNotFound)
	}

	var createResult *keycreator.CreateKeyResult
	if in.Usage == keyutil.KEY_USAGE_OPERATIONAL {
		createResult, err = s.kcClient.CreateOperationalKey(ctx, in.TraceID, in.ChainCode, coreKey.Bip44Path, accountIndexStart, uint32(in.Count), coreKey.Bip32KeyCiphertext, masterKey.KeyType)
	} else {
		createResult, err = s.kcClient.CreateUserKey(ctx, in.TraceID, in.ChainCode, coreKey.Bip44Path, accountIndexStart, uint32(in.Count), coreKey.Bip32KeyCiphertext, masterKey.KeyType)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: key creator CreateKey failed: %s", ErrNetwork, err)
	}

	pkixList := make([]*tbproto.PublicKeysRequest, 0, len(createResult.Keys))
	for _, key := range createResult.Keys {
		pkixList = append(pkixList, &tbproto.PublicKeysRequest{
			AccountIndex:  key.AccountIndex,
			PkixPubkeyPem: key.PublicKey,
		})
	}

	callRes, err := s.txClient.ConvertAddress(ctx, &tbproto.ConvertAddressRequest{
		TraceId: in.TraceID,
		Keys:    pkixList,
	}, in.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("%w: ConvertAddress failed: %s", ErrNetwork, err)
	}

	addrMap := make(map[uint32]string)
	for _, addr := range callRes.AddressList {
		addrMap[addr.AccountIndex] = addr.Address
	}

	keys := make([]*model.ChindKey, 0, len(createResult.Keys))
	addressInfos := make([]*coordinator.AddressInfo, 0, len(createResult.Keys))

	for _, key := range createResult.Keys {
		addr := addrMap[key.AccountIndex]
		keys = append(keys, &model.ChindKey{
			ChainCode:    in.ChainCode,
			KeyUsage:     uint8(in.Usage.ToUin32()),
			AccountIndex: key.AccountIndex,
			BIP44Path:    key.Bip44Path,
			KeyContext:   key.Context,
			Ciphertext:   key.PrivKeyCiphertext,
			PublicKey:    key.PublicKey,
			KeyAddress:   addr,
		})
		addressInfos = append(addressInfos, &coordinator.AddressInfo{
			AccountIndex: key.AccountIndex,
			Address:      addr,
		})
	}

	if err := s.repo.CreateKeys(ctx, keys); err != nil {
		return nil, fmt.Errorf("%w: failed to save keys: %s", ErrNetwork, err)
	}

	return addressInfos, nil
}

type VerifyAddressInput struct {
	TraceID   string
	ChainCode string
	Address   string
}

func (s *keyServiceImpl) VerifyAddress(ctx context.Context, in *VerifyAddressInput) (bool, error) {
	resp, err := s.txClient.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, fmt.Errorf("%w: VerifyAddress failed: %s", ErrNetwork, err)
	}
	return resp.IsValid, nil
}

type VerifyContractAddressInput struct {
	TraceID   string
	ChainCode string
	Address   string
}

func (s *keyServiceImpl) VerifyContractAddress(ctx context.Context, in *VerifyContractAddressInput) (bool, error) {
	resp, err := s.txClient.VerifyContractAddress(ctx, &tbproto.VerifyContractAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, fmt.Errorf("%w: VerifyContractAddress failed: %s", ErrNetwork, err)
	}
	return resp.IsValid, nil
}

type BalanceInput struct {
	TraceID     string
	ChainCode   string
	Coin        string
	IsBasicCoin bool
	FromAddress string
	Amount      string
	Contract    string
}

type BalanceResult struct {
	IsCoinSufficient  bool
	IsTokenSufficient bool
}

func (s *keyServiceImpl) CheckSufficientBalance(ctx context.Context, in *BalanceInput) (*BalanceResult, error) {
	resp, err := s.txClient.CheckSufficientBalance(ctx, &tbproto.CheckSufficientBalanceRequest{
		TraceId:     in.TraceID,
		ChainCode:   in.ChainCode,
		Coin:        in.Coin,
		IsBasicCoin: in.IsBasicCoin,
		FromAddress: in.FromAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: CheckSufficientBalance failed: %s", ErrNetwork, err)
	}
	return &BalanceResult{
		IsCoinSufficient:  resp.IsCoinSufficient,
		IsTokenSufficient: resp.IsTokenSufficient,
	}, nil
}

func validateTraceId(traceId string) error {
	if traceId == "" {
		return fmt.Errorf("trace_id is required")
	}
	if len(traceId) < 1 || len(traceId) > 36 {
		return fmt.Errorf("trace_id must be 1-36 characters")
	}
	return nil
}

func validateChainCode(chainCode string) error {
	if chainCode == "" {
		return fmt.Errorf("chain_code is required")
	}
	if len(chainCode) < 1 || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if strings.Contains(chainCode, " ") {
		return fmt.Errorf("chain_code cannot contain spaces")
	}
	return nil
}
