package txbuilder

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/koku-web3/go-koku/pkg/logko"
	tbgrpc "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
	"google.golang.org/grpc"
)

// ChainProvider 接口的设计作用于解耦客户端（Client）与链配置信息（如 RPC/gRPC 地址）的获取细节。
// 让 Client 只关心如何根据链代码获取链服务地址，无需关心背后实现原理。
type ChainProvider interface {
	GetChainByCode(chainCode string) (addr string, ok bool)
}

type Client struct {
	mu       sync.RWMutex
	chains   map[string]*ChainClient
	cfg      Config
	chainsPA ChainProvider
	closed   bool
}

type AcctAddrWithIndex struct {
	AccountIndex uint32
	Address      string
}

type PkixPubkeyPemWithIndex struct {
	AccountIndex  uint32
	PkixPubkeyPem string
}

func NewClient(cfg Config, chainsP ChainProvider) (*Client, error) {
	defaults := DefaultConfig()
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaults.DialTimeout
	}
	if cfg.KeepaliveTime <= 0 {
		cfg.KeepaliveTime = defaults.KeepaliveTime
	}
	if cfg.KeepaliveTimeout <= 0 {
		cfg.KeepaliveTimeout = defaults.KeepaliveTimeout
	}
	if cfg.MinConnectTimeout <= 0 {
		cfg.MinConnectTimeout = defaults.MinConnectTimeout
	}
	if cfg.MaxConnectTimeout <= 0 {
		cfg.MaxConnectTimeout = defaults.MaxConnectTimeout
	}
	if cfg.CircuitBreakerThreshold <= 0 {
		cfg.CircuitBreakerThreshold = defaults.CircuitBreakerThreshold
	}
	if cfg.CircuitBreakerWindow <= 0 {
		cfg.CircuitBreakerWindow = defaults.CircuitBreakerWindow
	}
	if !cfg.PermitWithoutStream {
		cfg.PermitWithoutStream = defaults.PermitWithoutStream
	}

	return &Client{
		chains:   make(map[string]*ChainClient),
		cfg:      cfg,
		chainsPA: chainsP,
	}, nil
}

func (c *Client) VerifyAddress(ctx context.Context, req *tbgrpc.VerifyAddressRequest, chainCode string) (*tbgrpc.VerifyAddressResponse, error) {
	log.Debug("Calling verify address", "trace_id", req.TraceId, "chain_code", chainCode, "address", req.Address)
	client, err := c.getClient(chainCode)
	if err != nil {
		return nil, err
	}
	return client.VerifyAddress(ctx, req)
}

func (c *Client) VerifyContractAddress(ctx context.Context, req *tbgrpc.VerifyContractAddressRequest, chainCode string) (*tbgrpc.VerifyContractAddressResponse, error) {
	log.Debug("Calling verify contract address", "trace_id", req.TraceId, "chain_code", chainCode, "address", req.Address)
	client, err := c.getClient(chainCode)
	if err != nil {
		return nil, err
	}
	return client.VerifyContractAddress(ctx, req)
}

func (c *Client) ConvertAddress(ctx context.Context, req *tbgrpc.ConvertAddressRequest, chainCode string) (*tbgrpc.ConvertAddressResponse, error) {
	log.Debug("Calling convert address", "trace_id", req.TraceId, "chain_code", chainCode)
	if len(req.Keys) == 0 {
		return nil, fmt.Errorf("keys is empty")
	}
	client, err := c.getClient(chainCode)
	if err != nil {
		return nil, err
	}
	return client.ConvertAddress(ctx, req)
}

func (c *Client) CheckSufficientBalance(ctx context.Context, req *tbgrpc.CheckSufficientBalanceRequest) (*tbgrpc.CheckSufficientBalanceResponse, error) {
	log.Debug("Calling check sufficient balance", "trace_id", req.TraceId, "chain_code", req.ChainCode, "coin", req.Coin, "from_address", req.FromAddress, "amount", req.Amount, "contract", req.Contract)
	client, err := c.getClient(req.ChainCode)
	if err != nil {
		log.Error("Failed to get chain client", "chain_code", req.ChainCode, "error", err.Error())
		return nil, err
	}
	return client.CheckSufficientBalance(ctx, req)
}

func (c *Client) BuildSignRawData(ctx context.Context, req *tbgrpc.BuildSignRawDataRequest) (*tbgrpc.BuildSignRawDataResponse, error) {
	log.Debug("Calling build sign raw data", "trace_id", req.TraceId, "chain_code", req.ChainCode, "coin", req.Coin, "coin_symbol", req.CoinSymbol, "from_address", req.FromAddress, "to_address", req.ToAddress, "amount", req.Amount, "contract", req.Contract)
	client, err := c.getClient(req.ChainCode)
	if err != nil {
		log.Error("Failed to get chain client", "chain_code", req.ChainCode, "error", err.Error())
		return nil, err
	}
	start := time.Now()
	res, err := client.BuildSignRawData(ctx, req)
	cost := time.Since(start)
	if err != nil {
		log.Error("Call TxBuilderClient.BuildSignRawData failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "time_cost_us", cost.Microseconds(), "error", err.Error())
		return nil, fmt.Errorf("call TxBuilderClient.BuildSignRawData failed: %w", err)
	}
	log.Info("Build transaction completed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "time_cost_us", cost.Microseconds())
	return res, nil
}

func (c *Client) TxBroadcast(ctx context.Context, in *tbgrpc.TxBroadcastRequest, chainCode string, opts ...grpc.CallOption) (*tbgrpc.TxBroadcastResponse, error) {
	log.Debug("Calling tx broadcast", "trace_id", in.TraceId, "chain_code", chainCode)
	client, err := c.getClient(chainCode)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	res, err := client.TxBroadcast(ctx, in, opts...)
	cost := time.Since(start)
	if err != nil {
		log.Error("Call TxBuilderClient.TxBroadcast failed", "trace_id", in.TraceId, "chain_code", chainCode, "time_cost_us", cost.Microseconds(), "error", err.Error())
		return nil, fmt.Errorf("call TxBuilderClient.TxBroadcast failed: %w", err)
	}
	log.Info("Broadcast transcation completed", "trace_id", in.TraceId, "chain_code", chainCode, "time_cost_us", cost.Microseconds())
	return res, nil
}

func (c *Client) getClient(chainCode string) (tbgrpc.TxBuilderClient, error) {
	cc, err := c.getOrCreate(chainCode)
	if err != nil {
		return nil, err
	}
	log.Debug("Get chain client", "chain_code", chainCode)
	return cc.GetClient()
}

// getOrCreate 用于获取或新建对应链的 ChainClient。
// 此方法实现了双重检查锁（double-checked locking），以保证在并发情况下资源只被初始化一次。
//
// 1. 首先使用读锁（RLock）快速检查链客户端是否已存在，避免无谓抢占写锁。
// 2. 如果未找到，再升级到写锁（Lock），此时需要再次检查（双重检查）链客户端是否已被其他协程创建，确保只有一个实例被创建。
// 3. 锁保护下的所有对 c.chains 和 c.closed 的操作都是并发安全的。
// 4. c.closed 状态均需在锁保护下判断，以防止关闭与使用同时发生导致竞态。
//
// 锁的正确使用保证了资源初始化的正确性和高并发下的效率。
func (c *Client) getOrCreate(chainCode string) (*ChainClient, error) {
	// 首先加读锁，允许其他 goroutine 读操作，提高并发性能
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	cc, ok := c.chains[chainCode]
	c.mu.RUnlock()
	if ok {
		return cc, nil
	}

	// 未找到则升级为写锁，准备新建 ChainClient
	c.mu.Lock()
	defer c.mu.Unlock()
	// 写锁下再次判断状态，避免并发关闭导致资源泄露
	if c.closed {
		return nil, ErrPoolClosed
	}
	// 双重检查，防止并发情况下重复创建
	cc, ok = c.chains[chainCode]
	if ok {
		return cc, nil
	}
	addr, ok := c.chainsPA.GetChainByCode(chainCode)
	if !ok || addr == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoAddress, chainCode)
	}
	cc, err := newChainClient(chainCode, addr, c.cfg)
	if err != nil {
		return nil, err
	}
	// 写锁保护下安全写入 map
	c.chains[chainCode] = cc
	return cc, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	chainCount := len(c.chains)
	for _, cc := range c.chains {
		_ = cc.Close()
	}
	c.chains = nil
	log.Info("TxBuilder client closed", "chain_count", chainCount)
	return nil
}

type ChainStats struct {
	ChainCode    string
	Addr         string
	CircuitState string
}

func (c *Client) Stats() []ChainStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ChainStats, 0, len(c.chains))
	for _, cc := range c.chains {
		out = append(out, ChainStats{
			ChainCode:    cc.ChainCode(),
			Addr:         cc.Addr(),
			CircuitState: cc.CircuitState().String(),
		})
	}
	return out
}
