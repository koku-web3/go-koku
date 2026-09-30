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
	"github.com/koku-web3/go-koku/pkg/errors"
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

type createKeyInfra struct {
	chain             *model.Chain
	corekey           *model.CoreKey
	accountIndexStart uint32
}

func NewKeyService(repo repository.KeyRepository, kc *keycreator.Client, tx *txbuilder.Client) key.KeyManager {
	return &keyService{repo: repo, kcClient: kc, txClient: tx}
}

func (s *keyService) Genesis(ctx context.Context, in *types.GenesisInput) error {
	traceID := in.TraceID
	chainCode := in.ChainCode
	if err := validateTraceId(traceID); err != nil {
		return err
	}
	if err := validateChainCode(chainCode); err != nil {
		return err
	}

	chain, err := s.repo.GetChainByCode(ctx, chainCode)
	if err != nil {
		return fmt.Errorf("repo.GetChainByCode from DB failed: %w", err)
	}

	existing, err := s.repo.GetMasterKeyByChainCode(ctx, chainCode)
	if err != nil {
		return fmt.Errorf("repo.GetMasterKeyByChainCode from DB failed: %w", err)
	}
	if existing != nil {
		log.Warn("Genesis failed: master_keys data exist", "trace_id", traceID, "chain_code", chainCode)
		return errors.New("Genesis data exist")
	}

	count, err := s.repo.GetCoreKeyCountByChainCode(ctx, chainCode)
	if err != nil {
		return fmt.Errorf("Repo.GetCoreKeyCountByChainCode from DB failed: %w", err)
	}
	if count > 0 {
		log.Warn("Genesis failed: core_keys data exist", "trace_id", traceID, "chain_code", chainCode)
		return errors.New("Genesis data exist")
	}

	result, err := s.kcClient.Genesis(ctx, traceID, chainCode, chain.KeyType)
	if err != nil {
		return fmt.Errorf("Call key-creator Genesis failed: %w", err)
	}

	masterKey := &model.MasterKey{
		ChainCode:      chainCode,
		SeedCiphertext: result.SeedCiphertext,
		DEK_Ciphertext: result.DEKCiphertext,
		Context:        result.Context,
		Bip44Path:      result.Bip44Path,
		IsDeleted:      false,
	}

	coreKeys := make([]*model.CoreKey, 0, len(result.DerivedKeys))
	for _, dk := range result.DerivedKeys {
		coreKeys = append(coreKeys, &model.CoreKey{
			ChainCode:          chainCode,
			KeyUsage:           uint8(dk.KeyUsage),
			Bip32KeyCiphertext: dk.Bip32KeyCiphertext,
			DEK_Ciphertext:     dk.DEKCiphertext,
			Context:            dk.Context,
			Bip44Path:          dk.Bip44Path,
			IsDeleted:          false,
		})
	}

	if err := s.repo.InsertGenesisRecordsAtomic(ctx, masterKey, coreKeys); err != nil {
		return fmt.Errorf("Failed to save genesis records to Database: %w", err)
	}

	return nil
}

func (s *keyService) getCreateKeyInfraData(ctx context.Context, traceID, chainCode string, usage uint32) (*createKeyInfra, error) {
	chain, err := s.repo.GetChainByCode(ctx, chainCode)
	if err != nil {
		log.Error("GetChainByCode from DB failed", "trace_id", traceID, "chain_code", chainCode, "error", err)
		return nil, errors.New("get chain data failed")
	}
	if chain == nil {
		log.Error("select data from chains not exist in Database", "trace_id", traceID, "chain_code", chainCode)
		return nil, errors.New("chain data does not exist")
	}

	accountIndexStart, err := s.repo.GetMaxAccountIndex(ctx, chainCode, usage)
	if err != nil {
		log.Error("GetMaxAccountIndex from DB failed", "trace_id", traceID, "chain_code", chainCode, "usage", usage, "error", err)
		return nil, errors.New("get max account index failed")
	}

	accountIndexStart++

	coreKey, err := s.repo.GetCoreKeyByChainCodeAndUsage(ctx, chainCode, usage)
	if err != nil {
		log.Error("GetCoreKeyByChainCodeAndUsage from DB failed", "trace_id", traceID, "chain_code", chainCode, "usage", usage, "error", err)
		return nil, errors.New("get core key data failed")
	}
	if coreKey == nil {
		log.Error("Select data from core_keys not exist in Database", "trace_id", traceID, "chain_code", chainCode, "usage", usage)
		return nil, errors.New("core key data does not exist")
	}

	if coreKey.Bip32KeyCiphertext == "" {
		log.Error("Data bip32key_ciphertext from core_keys is empty", "trace_id", traceID, "chain_code", chainCode, "usage", usage)
		return nil, errors.New("bip32key_ciphertext is empty")
	}
	if coreKey.DEK_Ciphertext == "" {
		log.Error("Data dek_ciphertext from core_keys is empty", "trace_id", traceID, "chain_code", chainCode, "usage", usage)
		return nil, errors.New("dek_ciphertext is empty")
	}
	return &createKeyInfra{chain: chain, corekey: coreKey, accountIndexStart: accountIndexStart}, nil
}

func (s *keyService) CreateKey(ctx context.Context, in *types.CreateKeyInput) ([]*coordinator.AddressInfo, error) {
	if err := validateTraceId(in.TraceID); err != nil {
		return nil, err
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return nil, err
	}
	if in.Count < 1 || in.Count > 50 {
		return nil, fmt.Errorf("count must be 1-50")
	}

	log.Debug("CreateKey request parameters verification passed", "trace_id", in.TraceID, "chain_code", in.ChainCode, "usage", in.Usage, "count", in.Count)

	infra, err := s.getCreateKeyInfraData(ctx, in.TraceID, in.ChainCode, in.Usage.ToUin32())
	if err != nil {
		return nil, err
	}

	var createResult *keycreator.CreateKeyResult
	params := keycreator.CreateKeyParams{
		TraceID:            in.TraceID,
		ChainCode:          in.ChainCode,
		Bip44Path:          infra.corekey.Bip44Path,
		AccountIndexStart:  infra.accountIndexStart,
		Count:              uint32(in.Count),
		Bip32KeyCiphertext: infra.corekey.Bip32KeyCiphertext,
		DEKCiphertext:      infra.corekey.DEK_Ciphertext,
		AlgoType:           infra.chain.KeyType,
	}
	if in.Usage == keyutil.KEY_USAGE_OPERATIONAL {
		createResult, err = s.kcClient.CreateOperationalKey(ctx, params)
	} else {
		createResult, err = s.kcClient.CreateUserKey(ctx, params)
	}
	if err != nil {
		return nil, fmt.Errorf("call key-creator create operational/user key failed: %w", err)
	}
	if len(createResult.Keys) == 0 {
		return nil, fmt.Errorf("call key-creator create operational/user key response keyList is empty")
	}

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
		return nil, fmt.Errorf("call txbuilder ConvertAddress failed: %w", err)
	}

	log.Debug("Call txbuilder to convert address success!", "trace_id", in.TraceID, "address_count", len(callRes.Keys))

	addrMap := make(map[uint32]string)
	for _, addr := range callRes.Keys {
		if addr.Address == "" {
			return nil, fmt.Errorf("Call txbuilder ConvertAddress response filed:Address is empty. accountIdx=%d", addr.AccountIndex)
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

	if err := s.repo.CreateKeys(ctx, keys); err != nil {
		return nil, fmt.Errorf("failed to save created keys to database: %s", err)
	}
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
	if err := validateTraceId(in.TraceID); err != nil {
		return false, err
	}
	if err := validateChainCode(in.ChainCode); err != nil {
		return false, err
	}
	if in.Address == "" {
		return false, fmt.Errorf("address is required")
	}
	resp, err := s.txClient.VerifyAddress(ctx, &tbproto.VerifyAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, err
	}
	return resp.IsValid, nil
}

func (s *keyService) VerifyContractAddress(ctx context.Context, in *types.VerifyContractAddressInput) (bool, error) {
	resp, err := s.txClient.VerifyContractAddress(ctx, &tbproto.VerifyContractAddressRequest{
		TraceId: in.TraceID,
		Address: in.Address,
	}, in.ChainCode)
	if err != nil {
		return false, fmt.Errorf("verify contract address failed: %w", err)
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
		return nil, err
	}

	return &types.BalanceResult{
		IsCoinSufficient:  resp.IsCoinSufficient,
		IsTokenSufficient: resp.IsTokenSufficient,
	}, nil
}

func validateTraceId(traceID string) error {
	if traceID == "" {
		return errors.New("trace_id is required")
	}
	if len(traceID) < 1 || len(traceID) > 36 {
		return fmt.Errorf("trace_id must be 1-36 characters")
	}
	return nil
}

func validateChainCode(chainCode string) error {
	if chainCode == "" {
		return errors.New("chain_code is required")
	}
	if len(chainCode) < 1 || len(chainCode) > 36 {
		return fmt.Errorf("chain_code must be 1-36 characters")
	}
	if strings.Contains(chainCode, " ") {
		return fmt.Errorf("chain_code cannot contain spaces")
	}
	return nil
}
