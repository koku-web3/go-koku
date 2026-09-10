package txbuilder

import (
	"context"
	"sync"
	"time"

	log "github.com/koku-web3/go-koku/pkg/logko"
	txbuildergrpc "github.com/koku-web3/go-koku/pkg/proto/txbuilder"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type ChainClient struct {
	chainCode string
	addr      string
	conn      *grpc.ClientConn
	client    txbuildergrpc.TxBuilderClient
	breaker   *CircuitBreaker

	mu     sync.RWMutex
	closed bool
}

func newChainClient(chainCode string, addr string, cfg Config) (*ChainClient, error) {
	keepaliveParams := keepalive.ClientParameters{
		Time:                time.Duration(cfg.KeepaliveTime) * time.Second,
		Timeout:             time.Duration(cfg.KeepaliveTimeout) * time.Second,
		PermitWithoutStream: cfg.PermitWithoutStream,
	}
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if cfg.KeepaliveTime > 0 {
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepaliveParams))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, err
	}

	cc := &ChainClient{
		chainCode: chainCode,
		addr:      addr,
		conn:      conn,
		client:    txbuildergrpc.NewTxBuilderClient(conn),
		breaker:   NewCircuitBreaker(cfg.CircuitBreakerThreshold, cfg.CircuitBreakerWindow),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DialTimeout)*time.Second)
	defer cancel()
	if err := cc.waitReady(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	log.Info("ChainClient: connected", "chain", chainCode, "addr", addr)
	return cc, nil
}

func (cc *ChainClient) waitReady(ctx context.Context) error {
	if cc.conn.GetState() == connectivity.Ready {
		return nil
	}
	if !cc.conn.WaitForStateChange(ctx, cc.conn.GetState()) {
		return ctx.Err()
	}
	if cc.conn.GetState() != connectivity.Ready {
		return context.DeadlineExceeded
	}
	return nil
}

func (cc *ChainClient) GetClient() (txbuildergrpc.TxBuilderClient, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	if cc.closed {
		return nil, ErrPoolClosed
	}
	if cc.breaker.IsOpen() {
		return nil, ErrCircuitOpen
	}
	return &circuitBreakerClient{client: cc.client, breaker: cc.breaker}, nil
}

func (cc *ChainClient) Close() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.closed {
		return nil
	}
	cc.closed = true
	if cc.conn != nil {
		return cc.conn.Close()
	}
	return nil
}

func (cc *ChainClient) ChainCode() string {
	return cc.chainCode
}

func (cc *ChainClient) Addr() string {
	return cc.addr
}

func (cc *ChainClient) CircuitState() CircuitState {
	return cc.breaker.State()
}

type circuitBreakerClient struct {
	client  txbuildergrpc.TxBuilderClient
	breaker *CircuitBreaker
}

func (c *circuitBreakerClient) VerifyAddress(ctx context.Context, in *txbuildergrpc.VerifyAddressRequest, opts ...grpc.CallOption) (*txbuildergrpc.VerifyAddressResponse, error) {
	resp, err := c.client.VerifyAddress(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) VerifyContractAddress(ctx context.Context, in *txbuildergrpc.VerifyContractAddressRequest, opts ...grpc.CallOption) (*txbuildergrpc.VerifyContractAddressResponse, error) {
	resp, err := c.client.VerifyContractAddress(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) ConvertAddress(ctx context.Context, in *txbuildergrpc.ConvertAddressRequest, opts ...grpc.CallOption) (*txbuildergrpc.ConvertAddressResponse, error) {
	resp, err := c.client.ConvertAddress(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) CheckSufficientBalance(ctx context.Context, in *txbuildergrpc.CheckSufficientBalanceRequest, opts ...grpc.CallOption) (*txbuildergrpc.CheckSufficientBalanceResponse, error) {
	resp, err := c.client.CheckSufficientBalance(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) BuildSignRawData(ctx context.Context, in *txbuildergrpc.BuildSignRawDataRequest, opts ...grpc.CallOption) (*txbuildergrpc.BuildSignRawDataResponse, error) {
	resp, err := c.client.BuildSignRawData(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) TxBroadcast(ctx context.Context, in *txbuildergrpc.TxBroadcastRequest, opts ...grpc.CallOption) (*txbuildergrpc.TxBroadcastResponse, error) {
	resp, err := c.client.TxBroadcast(ctx, in, opts...)
	c.recordResult(err)
	return resp, err
}

func (c *circuitBreakerClient) recordResult(err error) {
	if err != nil {
		c.breaker.RecordFailure()
	} else {
		c.breaker.RecordSuccess()
	}
}
