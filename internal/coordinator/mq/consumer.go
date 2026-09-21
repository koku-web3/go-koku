package mq

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/repository"
	"github.com/koku-web3/go-koku/internal/coordinator/tx"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/wagslane/go-rabbitmq"
)

type Consumer struct {
	cfg           config.MQConfig
	conn          *rabbitmq.Conn
	acct0Consumer *rabbitmq.Consumer
	acct1Consumer *rabbitmq.Consumer
	handler       *Handler
	ctx           context.Context
	stop          chan struct{}
	stopWg        sync.WaitGroup
}

func NewConsumer(ctx context.Context, cfg config.MQConfig, transferMgr tx.TransferManager, repo repository.KeyRepository) (*Consumer, error) {
	conn, err := rabbitmq.NewConn(
		cfg.URL,
		rabbitmq.WithConnectionOptionsLogging,
	)
	if err != nil {
		return nil, fmt.Errorf("connect to rabbitmq: %w", err)
	}

	ac0, err := newConsumer(
		conn,
		cfg.QueueAcct0,
		cfg.Exchange,
		cfg.ExchangeType,
		cfg.RoutingKeyAcct0,
		"c-acct0",
		cfg.PrefetchCount,
	)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.Error("failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("create consumer for %s: %w", cfg.QueueAcct0, err)
	}

	ac1, err := newConsumer(
		conn,
		cfg.QueueAcct1,
		cfg.Exchange,
		cfg.ExchangeType,
		cfg.RoutingKeyAcct1,
		"c-acct1",
		cfg.PrefetchCount,
	)
	if err != nil {
		ac0.Close()
		if closeErr := conn.Close(); closeErr != nil {
			log.Error("failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("create consumer for %s: %w", cfg.QueueAcct1, err)
	}

	return &Consumer{
		cfg:           cfg,
		conn:          conn,
		acct0Consumer: ac0,
		acct1Consumer: ac1,
		handler:       NewHandler(transferMgr, repo),
		ctx:           ctx,
		stop:          make(chan struct{}),
	}, nil
}

func newConsumer(
	conn *rabbitmq.Conn,
	queueName string,
	exchange string,
	exchangeType string,
	routingKey string,
	consumerName string,
	prefetchCount int,
) (*rabbitmq.Consumer, error) {
	return rabbitmq.NewConsumer(
		conn,
		queueName,
		rabbitmq.WithConsumerOptionsExchangeName(exchange),
		rabbitmq.WithConsumerOptionsExchangeKind(exchangeType),
		rabbitmq.WithConsumerOptionsExchangeDeclare,
		rabbitmq.WithConsumerOptionsRoutingKey(routingKey),
		rabbitmq.WithConsumerOptionsQueueDurable,
		rabbitmq.WithConsumerOptionsQOSPrefetch(prefetchCount),
		rabbitmq.WithConsumerOptionsConsumerName(consumerName),
		rabbitmq.WithConsumerOptionsLogging,
	)
}

func (c *Consumer) RunForever() error {
	c.stopWg.Add(2)
	go c.runLoop(c.acct0Consumer, c.cfg.QueueAcct0)
	go c.runLoop(c.acct1Consumer, c.cfg.QueueAcct1)

	log.Info("MQ Consumer started", "queue_acct0", c.cfg.QueueAcct0, "queue_acct1", c.cfg.QueueAcct1)

	<-c.ctx.Done()
	log.Info("MQ Consumer stopping...")

	c.acct0Consumer.CloseWithContext(c.ctx)
	c.acct1Consumer.CloseWithContext(c.ctx)

	c.stopWg.Wait()

	if err := c.conn.Close(); err != nil {
		log.Error("failed to close connection", "error", err)
	}
	log.Info("MQ Consumer stopped")
	return nil
}

func (c *Consumer) runLoop(consumer *rabbitmq.Consumer, queueName string) {
	defer c.stopWg.Done()

	handler := func(d rabbitmq.Delivery) rabbitmq.Action {
		start := time.Now()

		routingKey := d.RoutingKey
		if routingKey == "" {
			routingKey = queueName
		}

		traceID := c.extractHeader(d, "trace_id")
		bizID := c.extractHeader(d, "biz_id")

		msg, err := ParseMsg(d.Body)
		if err != nil {
			log.Error("parse msg failed, reject without requeue",
				"queue", queueName, "error", err)
			if nackErr := d.Nack(false, false); nackErr != nil {
				log.Error("failed to nack message", "error", nackErr)
			}
			return rabbitmq.NackDiscard
		}

		if traceID != "" {
			msg.TraceID = traceID
		}
		if bizID != "" {
			msg.BizID = bizID
		}

		err = c.handler.Handle(c.ctx, routingKey, msg)
		elapsed := time.Since(start)

		if err == nil {
			if ackErr := d.Ack(false); ackErr != nil {
				log.Error("failed to ack message", "error", ackErr)
			}
			log.Info("msg processed successfully",
				"trace_id", msg.TraceID, "biz_id", msg.BizID,
				"chain_code", msg.ChainCode, "queue", queueName,
				"elapsed_ms", elapsed.Milliseconds())
			return rabbitmq.Ack
		}

		if IsPermanent(err) {
			if nackErr := d.Nack(false, false); nackErr != nil {
				log.Error("failed to nack message", "error", nackErr)
			}
			log.Error("msg processed failed (permanent), reject without requeue",
				"trace_id", msg.TraceID, "biz_id", msg.BizID,
				"queue", queueName, "error", err,
				"elapsed_ms", elapsed.Milliseconds())
			return rabbitmq.NackDiscard
		}

		if nackErr := d.Nack(false, true); nackErr != nil {
			log.Error("failed to nack message", "error", nackErr)
		}
		log.Error("msg processed failed (transient), requeue for retry",
			"trace_id", msg.TraceID, "biz_id", msg.BizID,
			"queue", queueName, "error", err,
			"elapsed_ms", elapsed.Milliseconds())
		return rabbitmq.NackRequeue
	}

	if err := consumer.Run(handler); err != nil {
		log.Error("consumer run error", "queue", queueName, "error", err)
	}
}

func (c *Consumer) extractHeader(d rabbitmq.Delivery, key string) string {
	if d.Headers == nil {
		return ""
	}
	if v, ok := d.Headers[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
