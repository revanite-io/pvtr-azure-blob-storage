package reusable_steps

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/revanite-io/pvtr-azure-blob-storage/data"
)

func TestVerifyPayload_ValidPayload(t *testing.T) {
	p := data.Payload{}
	_, msg := VerifyPayload(p)
	if msg != "" {
		t.Errorf("expected no message, got %q", msg)
	}
}

func TestVerifyPayload_WrongType(t *testing.T) {
	_, msg := VerifyPayload("not a payload")
	if msg == "" {
		t.Error("expected error message for wrong type")
	}
}

func TestVerifyPayload_Nil(t *testing.T) {
	_, msg := VerifyPayload(nil)
	if msg == "" {
		t.Error("expected error message for nil")
	}
}

func TestNotImplemented(t *testing.T) {
	result, msg, _ := NotImplemented(data.Payload{})
	if result != gemara.NeedsReview {
		t.Errorf("result = %v, want NeedsReview", result)
	}
	if msg != "Not implemented" {
		t.Errorf("msg = %q", msg)
	}
}

func TestAzureBuiltIn_ValidPayload(t *testing.T) {
	result, _, _ := AzureBuiltIn(data.Payload{})
	if result != gemara.Passed {
		t.Errorf("result = %v, want Passed", result)
	}
}

func TestAzureBuiltIn_InvalidPayload(t *testing.T) {
	result, msg, _ := AzureBuiltIn("wrong")
	if result != gemara.Unknown {
		t.Errorf("result = %v, want Unknown", result)
	}
	if msg == "" {
		t.Error("expected error message")
	}
}
