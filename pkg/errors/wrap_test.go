package errors

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInvalidArgument(t *testing.T) {
	err := InvalidArgument("address")
	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected status error, got %T", err)
	}
	if s.Code() != codes.InvalidArgument {
		t.Errorf("code: got %v, want %v", s.Code(), codes.InvalidArgument)
	}
	if s.Message() != "invalid address" {
		t.Errorf("message: got %q, want %q", s.Message(), "invalid address")
	}
}

func TestInvalidArgumentErr(t *testing.T) {
	inner := status.Error(codes.InvalidArgument, "trace_id is required")
	err := InvalidArgumentErr(inner)
	s, _ := status.FromError(err)
	if s.Code() != codes.InvalidArgument {
		t.Errorf("code: got %v, want %v", s.Code(), codes.InvalidArgument)
	}
	if s.Message() != "trace_id is required" {
		t.Errorf("message: got %q, want %q", s.Message(), "trace_id is required")
	}
}

func TestInvalidArgumentf(t *testing.T) {
	err := InvalidArgumentf("field %s is invalid", "chain_code")
	s, _ := status.FromError(err)
	if s.Code() != codes.InvalidArgument {
		t.Errorf("code: got %v, want %v", s.Code(), codes.InvalidArgument)
	}
	if s.Message() != "field chain_code is invalid" {
		t.Errorf("message: got %q", s.Message())
	}
}

func TestInternal(t *testing.T) {
	err := Internal()
	s, _ := status.FromError(err)
	if s.Code() != codes.Internal {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Internal)
	}
	if s.Message() != "" {
		t.Errorf("message: got %q, want empty", s.Message())
	}
}

func TestNotFound(t *testing.T) {
	err := NotFound("key not found")
	s, _ := status.FromError(err)
	if s.Code() != codes.NotFound {
		t.Errorf("code: got %v, want %v", s.Code(), codes.NotFound)
	}
	if s.Message() != "key not found" {
		t.Errorf("message: got %q, want %q", s.Message(), "key not found")
	}
}

func TestNotFoundf(t *testing.T) {
	err := NotFoundf("key %d not found", 42)
	s, _ := status.FromError(err)
	if s.Code() != codes.NotFound {
		t.Errorf("code: got %v, want %v", s.Code(), codes.NotFound)
	}
	if s.Message() != "key 42 not found" {
		t.Errorf("message: got %q", s.Message())
	}
}

func TestAlreadyExists(t *testing.T) {
	err := AlreadyExists("genesis already exists")
	s, _ := status.FromError(err)
	if s.Code() != codes.AlreadyExists {
		t.Errorf("code: got %v, want %v", s.Code(), codes.AlreadyExists)
	}
}

func TestAlreadyExistsf(t *testing.T) {
	err := AlreadyExistsf("chain %s already initialized", "ethereum")
	s, _ := status.FromError(err)
	if s.Code() != codes.AlreadyExists {
		t.Errorf("code: got %v, want %v", s.Code(), codes.AlreadyExists)
	}
}

func TestPermissionDenied(t *testing.T) {
	err := PermissionDenied("not authorized")
	s, _ := status.FromError(err)
	if s.Code() != codes.PermissionDenied {
		t.Errorf("code: got %v, want %v", s.Code(), codes.PermissionDenied)
	}
}

func TestPermissionDeniedf(t *testing.T) {
	err := PermissionDeniedf("user %s cannot access resource %s", "alice", "key-1")
	s, _ := status.FromError(err)
	if s.Code() != codes.PermissionDenied {
		t.Errorf("code: got %v, want %v", s.Code(), codes.PermissionDenied)
	}
}

func TestFailedPrecondition(t *testing.T) {
	err := FailedPrecondition("insufficient balance")
	s, _ := status.FromError(err)
	if s.Code() != codes.FailedPrecondition {
		t.Errorf("code: got %v, want %v", s.Code(), codes.FailedPrecondition)
	}
}

func TestFailedPreconditionf(t *testing.T) {
	err := FailedPreconditionf("balance %s < required %s", "0.5", "1.0")
	s, _ := status.FromError(err)
	if s.Code() != codes.FailedPrecondition {
		t.Errorf("code: got %v, want %v", s.Code(), codes.FailedPrecondition)
	}
}

func TestOutOfRange(t *testing.T) {
	err := OutOfRange("offset exceeds file size")
	s, _ := status.FromError(err)
	if s.Code() != codes.OutOfRange {
		t.Errorf("code: got %v, want %v", s.Code(), codes.OutOfRange)
	}
}

func TestOutOfRangef(t *testing.T) {
	err := OutOfRangef("page %d out of %d", 99, 10)
	s, _ := status.FromError(err)
	if s.Code() != codes.OutOfRange {
		t.Errorf("code: got %v, want %v", s.Code(), codes.OutOfRange)
	}
}

func TestUnimplemented(t *testing.T) {
	err := Unimplemented("operation not supported")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unimplemented {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unimplemented)
	}
}

func TestUnimplementedf(t *testing.T) {
	err := Unimplementedf("chain %s not supported", "unknown")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unimplemented {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unimplemented)
	}
}

func TestUnavailable(t *testing.T) {
	err := Unavailable("service temporarily unavailable")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unavailable {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unavailable)
	}
}

func TestUnavailablef(t *testing.T) {
	err := Unavailablef("node %s is down", "node-3")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unavailable {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unavailable)
	}
}

func TestUnauthenticated(t *testing.T) {
	err := Unauthenticated("token expired")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unauthenticated {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unauthenticated)
	}
}

func TestUnauthenticatedf(t *testing.T) {
	err := Unauthenticatedf("invalid signature for user %s", "bob")
	s, _ := status.FromError(err)
	if s.Code() != codes.Unauthenticated {
		t.Errorf("code: got %v, want %v", s.Code(), codes.Unauthenticated)
	}
}
