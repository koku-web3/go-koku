package middleware

import (
	"context"
	"time"

	log "github.com/koku-web3/go-koku/pkg/logko"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a gRPC unary server interceptor that logs
// method entry (Debug) and exit (Info/Warn/Error) with time_cost_ms and
// structured fields following the logging specification.
//
// Entry Debug prints: "Method received", trace_id, and whitelisted request fields.
// Exit logs are chosen by gRPC status code:
//   - OK                        → Info  with time_cost_ms
//   - InvalidArgument           → Warn  with trace_id + error
//   - FailedPrecondition        → Warn  with trace_id + error
//   - NotFound / AlreadyExists  → Warn  with trace_id + error
//   - PermissionDenied          → Warn  with trace_id + error
//   - Unauthenticated          → Error with trace_id + error
//   - Unavailable               → Error with trace_id + error
//   - Internal / Unknown       → Error with trace_id + error
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

	// Entry Debug: trace_id must be first field
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
	default: // codes.Internal, codes.Unknown, etc.
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

// extractTraceID tries to extract trace_id from the request by checking
// the most common field names. Returns empty string if not found.
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
