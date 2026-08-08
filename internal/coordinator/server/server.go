package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/koku-web3/go-koku/internal/coordinator/chain"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/middleware"
)

type Server struct {
	srv     *http.Server
	service *chain.ChainService
}

func NewServer(service *chain.ChainService, host string, port int, readHeaderTimeout int) *Server {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.HTTPLogger())

	router.GET("/health", service.HealthCheck)

	router.POST("/api/keys", service.CreateMasterKey)
	router.GET("/api/keys", service.ListKeys)
	router.GET("/api/keys/:key_name", service.ReadKey)

	router.POST("/api/sign", service.SignMessage)
	router.POST("/api/verify", service.VerifySignature)

	addr := fmt.Sprintf("%s:%d", host, port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: time.Duration(readHeaderTimeout) * time.Second,
	}

	return &Server{
		srv:     srv,
		service: service,
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.service.StartTokenRefresh(ctx)

	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("Shutting down HTTP server")

		// 这里使用 context.Background() 而不是 ctx
		// 因为 ctx 是一个 Cancel 类型的 context，外部执行 cancel() 函数后
		// 会令 Shutdown() 内部直接 return，忽略未关闭的空闲连接（如果有）
		if err := s.srv.Shutdown(context.Background()); err != nil {
			log.Error("failed to shutdown server", "error", err)
		}
		log.Info("HTTP server has closed")
		// do sth after HTTP server shutdown

		close(shutdownCh)
	}()

	log.Info("Starting Coordinator", "address", s.srv.Addr)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// 使用一个channel阻塞，直到收到 close 信号才继续执行
	// 这样可以保证 上面的 “HTTP server has closed” 日志能正常输出
	<-shutdownCh
	return nil
}
