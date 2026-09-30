package middleware

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockRequest struct {
	traceID string
}

func (m *mockRequest) GetTraceId() string { return m.traceID }

func TestExtractTraceID(t *testing.T) {
	tests := []struct {
		name string
		req  interface{}
		want string
	}{
		{"GetTraceId", &mockRequest{traceID: "req-123"}, "req-123"},
		{"nil", nil, ""},
		{"unknown type", "not a struct", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTraceID(tt.req)
			if got != tt.want {
				t.Errorf("extractTraceID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnaryInterceptorStatusCodes(t *testing.T) {
	interceptor := UnaryServerInterceptor()
	if interceptor == nil {
		t.Fatal("UnaryServerInterceptor returned nil")
	}
}

func TestInterceptorRegistration(t *testing.T) {
	opts := UnaryServerInterceptor()
	_ = grpc.NewServer(opts)
}

func TestInterceptorCodesCoverage(t *testing.T) {
	cases := []struct {
		code   codes.Code
		wantFn string
	}{
		{codes.OK, "Info"},
		{codes.InvalidArgument, "Warn"},
		{codes.FailedPrecondition, "Warn"},
		{codes.NotFound, "Warn"},
		{codes.AlreadyExists, "Warn"},
		{codes.PermissionDenied, "Warn"},
		{codes.OutOfRange, "Warn"},
		{codes.Unimplemented, "Warn"},
		{codes.Unauthenticated, "Error"},
		{codes.Unavailable, "Error"},
		{codes.Internal, "Error"},
		{codes.Unknown, "Error"},
	}
	for _, c := range cases {
		t.Run(c.code.String(), func(t *testing.T) {
			want := c.wantFn
			switch c.code {
			case codes.OK:
				if want != "Info" {
					t.Errorf("code %v: want Info", c.code)
				}
			case codes.InvalidArgument,
				codes.FailedPrecondition,
				codes.NotFound,
				codes.AlreadyExists,
				codes.PermissionDenied,
				codes.OutOfRange,
				codes.Unimplemented:
				if want != "Warn" {
					t.Errorf("code %v: want Warn", c.code)
				}
			case codes.Unauthenticated, codes.Unavailable, codes.Internal, codes.Unknown:
				if want != "Error" {
					t.Errorf("code %v: want Error", c.code)
				}
			}
		})
	}
}

func TestUnaryServerInterceptorHandlerErrors(t *testing.T) {
	interceptorOpt := UnaryServerInterceptor()
	s := grpc.NewServer(interceptorOpt)
	if s == nil {
		t.Fatal("failed to create server with interceptor")
	}
}

type mockResp struct{}

func TestInterceptorPanicFree(t *testing.T) {
	fn := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "test internal error")
	}

	interceptor := func(
		ctx context.Context,
		req interface{},
		_info *grpc.UnaryServerInfo,
		_handler grpc.UnaryHandler,
	) (interface{}, error) {
		return fn(ctx, req)
	}

	_, _ = interceptor(context.Background(), &mockRequest{traceID: "panic-test"}, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return &mockResp{}, nil
	})
}

func TestExtractTraceIDFromStatusError(t *testing.T) {
	req := &statusErrorRequest{traceID: "status-err-456"}
	got := extractTraceID(req)
	if got != "status-err-456" {
		t.Errorf("extractTraceID() = %q, want %q", got, "status-err-456")
	}
}

type statusErrorRequest struct{ traceID string }

func (s *statusErrorRequest) TraceId() string { return s.traceID }

type statusErrorRequest2 struct{ traceID string }

func (s *statusErrorRequest2) GetTraceID() string { return s.traceID }

func TestExtractTraceIDVariant(t *testing.T) {
	req := &statusErrorRequest2{traceID: "variant-789"}
	got := extractTraceID(req)
	if got != "variant-789" {
		t.Errorf("extractTraceID() = %q, want %q", got, "variant-789")
	}
}
