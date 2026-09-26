package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/coordinator/infra/keycreator"
	"github.com/koku-web3/go-koku/internal/coordinator/infra/txbuilder"
	"github.com/koku-web3/go-koku/internal/coordinator/key"
	"github.com/koku-web3/go-koku/internal/coordinator/model"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/internal/coordinator/types"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	log "github.com/koku-web3/go-koku/pkg/logko"
	coordinator "github.com/koku-web3/go-koku/pkg/proto/coordinator"
	tbproto "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
)

type keyService struct {
	repo     repository.KeyRepository
	kcClient *keycreator.Client
	txClient *txbuilder.Client
}

func NewKeyService(repo repository.KeyRepository, kc *keycreator.Client, tx *txbuilder.Client) key.KeyManager {
	return &keyService{repo: repo, kcClient: kc, txClient: tx}
}

func (s *keyService) Genesis(ctx context.Context, in *types.GenesisInput) error {
	if err := validateTraceId(in.TraceID); err != nil {
		return fmt.Errorf("%w: %s", key.ErrInvalidParam, err)
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return fmt.Errorf("%w: %s", key.ErrInvalidParam, err)
	}

	chain, err := s.repo.GetChainByCode(ctx, in.ChainCode)
	if err != nil {
		return fmt.Errorf("%w: %s chain data not found %s", key.ErrChainNotFound, in.ChainCode, err)
	}

	existing, err := s.repo.GetMasterKeyByChainCode(ctx, in.ChainCode)
	if err != nil {
		return fmt.Errorf("%w: failed to check master key: %s", key.ErrNetwork, err)
	}
	if existing != nil {
		return fmt.Errorf("%w: master keys already exist for chain %s", key.ErrGenesisExists, in.ChainCode)
	}

	count, err := s.repo.GetCoreKeyCountByChainCode(ctx, in.ChainCode)
	if err != nil {
		return fmt.Errorf("%w: failed to check core keys: %s", key.ErrNetwork, err)
	}
	if count > 0 {
		return fmt.Errorf("%w: core keys already exist for chain %s", key.ErrGenesisExists, in.ChainCode)
	}

	result, err := s.kcClient.Genesis(ctx, in.TraceID, in.ChainCode, chain.KeyType)
	if err != nil {
		return fmt.Errorf("%w: key creator genesis failed: %s", key.ErrNetwork, err)
	}

	masterKey := &model.MasterKey{
		ChainCode:      in.ChainCode,
		SeedCiphertext: result.SeedCiphertext,
		DEK_Ciphertext: result.DEKCiphertext,
		Context:        result.Context,
		Bip44Path:      result.Bip44Path,
		IsDeleted:      false,
	}

	coreKeys := make([]*model.CoreKey, 0, len(result.DerivedKeys))
	for _, dk := range result.DerivedKeys {
		coreKeys = append(coreKeys, &model.CoreKey{
			ChainCode:          in.ChainCode,
			KeyUsage:           uint8(dk.KeyUsage),
			Bip32KeyCiphertext: dk.Bip32KeyCiphertext,
			DEK_Ciphertext:     dk.DEKCiphertext,
			Context:            dk.Context,
			Bip44Path:          dk.Bip44Path,
			IsDeleted:          false,
		})
	}

	if err := s.repo.InsertGenesisRecordsAtomic(ctx, masterKey, coreKeys); err != nil {
		return fmt.Errorf("%w: failed to save genesis records: %s", key.ErrNetwork, err)
	}

	return nil
}

func (s *keyService) CreateKey(ctx context.Context, in *types.CreateKeyInput) ([]*coordinator.AddressInfo, error) {
	if err := validateTraceId(in.TraceID); err != nil {
		return nil, fmt.Errorf("%w: %s", key.ErrInvalidParam, err)
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return nil, fmt.Errorf("%w: %s", key.ErrInvalidParam, err)
	}
	if in.Count < 1 || in.Count > 50 {
		return nil, fmt.Errorf("%w: count must be 1-50", key.ErrInvalidParam)
	}

	log.Info("[CreateKey] starting", "trace_id", in.TraceID, "chain_code", in.ChainCode, "usage", in.Usage, "count", in.Count)

	maxIndex, err := s.repo.GetMaxAccountIndex(ctx, in.ChainCode, in.Usage.ToUin32())
	if err != nil {
		return nil, fmt.Errorf("%w: GetMaxAccountIndex failed: %s", key.ErrNetwork, err)
	}
	accountIndexStart := maxIndex + 1

	coreKey, err := s.repo.GetCoreKeyByChainCodeAndUsage(ctx, in.ChainCode, in.Usage.ToUin32())
	if err != nil {
		return nil, fmt.Errorf("%w: GetCoreKeyByChainCodeAndUsage failed: %s", key.ErrNetwork, err)
	}
	if coreKey == nil {
		return nil, fmt.Errorf("%w: core key not found, run genesis first", key.ErrKeyNotFound)
	}

	chain, err := s.repo.GetChainByCode(ctx, in.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("%w: GetChainByCode failed: %s", key.ErrNetwork, err)
	}
	if chain == nil {
		return nil, fmt.Errorf("%w: chain data not found, run genesis first", key.ErrKeyNotFound)
	}

	log.Debug("[CreateKey] calling key creator", "trace_id", in.TraceID, "account_index_start", accountIndexStart)

	var createResult *keycreator.CreateKeyResult
	params := keycreator.CreateKeyParams{
		TraceID:            in.TraceID,
		ChainCode:          in.ChainCode,
		Bip44Path:          coreKey.Bip44Path,
		AccountIndexStart:  accountIndexStart,
		Count:              uint32(in.Count),
		Bip32KeyCiphertext: coreKey.Bip32KeyCiphertext,
		DEKCiphertext:      coreKey.DEK_Ciphertext,
		AlgoType:           chain.KeyType,
	}
	if in.Usage == keyutil.KEY_USAGE_OPERATIONAL {
		createResult, err = s.kcClient.CreateOperationalKey(ctx, params)
	} else {
		createResult, err = s.kcClient.CreateUserKey(ctx, params)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: key creator CreateKey failed: %s", key.ErrNetwork, err)
	}

	log.Debug("[CreateKey] converting addresses", "trace_id", in.TraceID, "key_count", len(createResult.Keys))

	pkixList := make([]*tbproto.PublicKeysRequest, 0, len(createResult.Keys))
	for _, key := range createResult.Keys {
		if err := validateCallCreateResponse(key); err != nil {
			return nil, err
		}
		pkixList = append(pkixList, &tbproto.PublicKeysRequest{
			AccountIndex:  key.AccountIndex,
			PkixPubkeyPem: key.PublicKey,
		})
	}

	callRes, err := s.txClient.ConvertAddress(ctx, &tbproto.ConvertAddressRequest{TraceId: in.TraceID, Keys: pkixList}, in.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("%w: ConvertAddress failed: %s", key.ErrNetwork, err)
	}

	log.Debug("[CreateKey] ConvertAddress response success", "trace_id", in.TraceID, "address_count", len(callRes.Keys))

	addrMap := make(map[uint32]string)
	for _, addr := range callRes.Keys {
		if addr.Address == "" {
			return nil, fmt.Errorf("response filed:Address is empty")
		}
		addrMap[addr.AccountIndex] = addr.Address
	}

	keys := make([]*model.ChindKey, 0, len(createResult.Keys))
	addressInfos := make([]*coordinator.AddressInfo, 0, len(createResult.Keys))

	for _, key := range createResult.Keys {
		addr := addrMap[key.AccountIndex]
		keys = append(keys, &model.ChindKey{
			ChainCode:      in.ChainCode,
			KeyUsage:       uint8(in.Usage.ToUin32()),
			AccountIndex:   key.AccountIndex,
			BIP44Path:      key.Bip44Path,
			KeyContext:     key.Context,
			Ciphertext:     key.PrivKeyCiphertext,
			DEK_Ciphertext: key.DEKCiphertext,
			PublicKey:      key.PublicKey,
			KeyAddress:     addr,
		})
		addressInfos = append(addressInfos, &coordinator.AddressInfo{
			AccountIndex: key.AccountIndex,
			Address:      addr,
		})
	}

	log.Debug("[CreateKey] saving keys to db", "trace_id", in.TraceID, "key_count", len(keys))

	if err := s.repo.CreateKeys(ctx, keys); err != nil {
		return nil, fmt.Errorf("%w: failed to save keys: %s", key.ErrNetwork, err)
	}
	log.Info("[CreateKey] completed", "trace_id", in.TraceID, "address_count", len(addressInfos))
	return addressInfos, nil
}

func validateCallCreateResponse(key keycreator.DerivedChildKeyResult) error {
	if key.PrivKeyCiphertext == "" {
		return fmt.Errorf("response filed:PrivKeyCiphertext is empty")
	}
	if key.Bip44Path == "" {
		return fmt.Errorf("response filed:Bip44Path is empty")
	}
	if key.Context == "" {
		return fmt.Errorf("response filed:Context is empty")
	}
	if key.DEKCiphertext == "" {
		return fmt.Errorf("response filed:DEKCiphertext is empty")
	}
	if key.PublicKey == "" {
		return fmt.Errorf("response filed:PublicKey is empty")
	}
	return nil
}

func (s *keyService) VerifyAddress(ctx context.Context, in *types.VerifyAddressInput) (bool, error) {
	resp, err := s.txClient.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, fmt.Errorf("%w: VerifyAddress failed: %s", key.ErrNetwork, err)
	}
	return resp.IsValid, nil
}

func (s *keyService) VerifyContractAddress(ctx context.Context, in *types.VerifyContractAddressInput) (bool, error) {
	resp, err := s.txClient.VerifyContractAddress(ctx, &tbproto.VerifyContractAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, fmt.Errorf("%w: VerifyContractAddress failed: %s", key.ErrNetwork, err)
	}
	return resp.IsValid, nil
}

func (s *keyService) CheckSufficientBalance(ctx context.Context, in *types.BalanceInput) (*types.BalanceResult, error) {
	resp, err := s.txClient.CheckSufficientBalance(ctx, &tbproto.CheckSufficientBalanceRequest{
		TraceId:     in.TraceID,
		ChainCode:   in.ChainCode,
		Coin:        in.Coin,
		FromAddress: in.FromAddress,
		Amount:      in.Amount,
		Contract:    in.Contract,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: CheckSufficientBalance failed: %s", key.ErrNetwork, err)
	}
	return &types.BalanceResult{
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
