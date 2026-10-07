package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/koku-web3/logko"
)

type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

var allowedHeaders = map[string]bool{
	"Content-Type":     true,
	"User-Agent":       true,
	"X-Request-Id":     true,
	"X-Correlation-Id": true,
}

func HTTPLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
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

		headers := make(map[string]string)
		for k, v := range c.Request.Header {
			if allowedHeaders[k] {
				headers[k] = v[0]
			} else {
				headers[k] = "[REDACTED]"
			}
		}

		requestBodyLen := len(requestBody)
		responseBodyLen := rw.body.Len()

		if c.Writer.Status() >= 500 {
			log.Error("HTTP request completed",
				"status", c.Writer.Status(),
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"time_cost_ms", latency.Milliseconds(),
				"headers", headers,
				"request_body_length", requestBodyLen,
				"response_body_length", responseBodyLen,
			)
		} else if c.Writer.Status() >= 400 {
			log.Warn("HTTP request completed",
				"status", c.Writer.Status(),
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"time_cost_ms", latency.Milliseconds(),
				"headers", headers,
				"request_body_length", requestBodyLen,
				"response_body_length", responseBodyLen,
			)
		} else {
			log.Info("HTTP request completed",
				"status", c.Writer.Status(),
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"ip", c.ClientIP(),
				"time_cost_ms", latency.Milliseconds(),
				"headers", headers,
				"request_body_length", requestBodyLen,
				"response_body_length", responseBodyLen,
			)
		}
	}
}
