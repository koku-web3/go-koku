package middleware

import (
	"context"
	"time"

	log "github.com/koku-web3/logko"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor 返回一个 gRPC 的一元服务器拦截器，负责日志输出：
// 方法入口（Debug）和方法返回（Info/Warn/Error），日志包含 time_cost_ms 及
// 按规范结构化字段。
//
// 入口 Debug 日志输出："Method received"、trace_id 以及白名单请求字段。
// 出口日志根据 gRPC 状态码分别：
//   - OK                        → Info，包含 time_cost_ms
//   - InvalidArgument           → Warn，包含 trace_id 和 error
//   - FailedPrecondition        → Warn，包含 trace_id 和 error
//   - NotFound / AlreadyExists  → Warn，包含 trace_id 和 error
//   - PermissionDenied          → Warn，包含 trace_id 和 error
//   - Unauthenticated           → Error，包含 trace_id 和 error
//   - Unavailable               → Error，包含 trace_id 和 error
//   - Internal / Unknown        → Error，包含 trace_id 和 error
func UnaryServerInterceptor() grpc.ServerOption {
	return grpc.UnaryInterceptor(unaryServerInterceptor)
}

func unaryServerInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()

	traceID := extractTraceID(req)

	// 入口 Debug 日志：trace_id 必须是第一个字段
	log.Debug("gRPC method received",
		"trace_id", traceID,
		"method", info.FullMethod,
	)

	resp, err := handler(ctx, req)
	cost := time.Since(start)
	costMs := cost.Milliseconds()

	if err == nil {
		log.Info("gRPC method succeeded",
			"trace_id", traceID,
			"method", info.FullMethod,
			"time_cost_ms", costMs,
		)
		return resp, nil
	}

	st, ok := status.FromError(err)
	if !ok {
		st = status.New(codes.Unknown, err.Error())
	}

	switch st.Code() {
	case codes.InvalidArgument,
		codes.FailedPrecondition,
		codes.NotFound,
		codes.AlreadyExists,
		codes.PermissionDenied,
		codes.OutOfRange,
		codes.Unimplemented:
		log.Warn("gRPC method failed",
			"trace_id", traceID,
			"method", info.FullMethod,
			"code", st.Code().String(),
			"error", err,
			"time_cost_ms", costMs,
		)
	case codes.Unauthenticated,
		codes.Unavailable:
		log.Error("gRPC method failed",
			"trace_id", traceID,
			"method", info.FullMethod,
			"code", st.Code().String(),
			"error", err,
			"time_cost_ms", costMs,
		)
	default: // codes.Internal, codes.Unknown, 等
		log.Error("gRPC method failed",
			"trace_id", traceID,
			"method", info.FullMethod,
			"code", st.Code().String(),
			"error", err,
			"time_cost_ms", costMs,
		)
	}

	return resp, err
}

// extractTraceID 尝试通过检测常见字段名从请求中提取 trace_id。
// 如果未找到，则返回空字符串。
func extractTraceID(req interface{}) string {
	switch r := req.(type) {
	case interface{ GetTraceId() string }:
		return r.GetTraceId()
	case interface{ TraceId() string }:
		return r.TraceId()
	case interface{ GetTraceID() string }:
		return r.GetTraceID()
	default:
		return ""
	}
}
