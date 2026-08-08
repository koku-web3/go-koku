package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/koku-web3/go-koku/pkg/logko"
)

type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func HTTPLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := log.Root()

		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		var requestBody []byte
		if c.Request.Body != nil {
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		rw := &responseWriter{
			ResponseWriter: c.Writer,
			body:           bytes.NewBuffer(nil),
		}
		c.Writer = rw

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		headers := make(map[string]interface{})
		for k, v := range c.Request.Header {
			if k == "Authorization" || k == "X-Vault-Token" || k == "Cookie" {
				headers[k] = "[REDACTED]"
			} else {
				headers[k] = v[0]
			}
		}

		var respBody string
		if rw.body.Len() > 0 {
			body := rw.body.Bytes()
			if len(body) > 1024 {
				respBody = string(body[:1024]) + "... [truncated]"
			} else {
				respBody = string(body)
			}
		}

		if status >= 500 {
			logger.Error("HTTP request completed with server error",
				"status", status,
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"latency", latency.String(),
				"headers", headers,
				"request_body", string(requestBody),
				"response_body", respBody,
			)
		} else if status >= 400 {
			logger.Warn("HTTP request completed with client error",
				"status", status,
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"latency", latency.String(),
				"headers", headers,
				"request_body", string(requestBody),
				"response_body", respBody,
			)
		} else {
			logger.Info("HTTP request completed",
				"status", status,
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"latency", latency.String(),
				"headers", headers,
				"request_body", string(requestBody),
				"response_body", respBody,
			)
		}
	}
}
