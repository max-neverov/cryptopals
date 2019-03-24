package cryptopals

import (
	"bytes"
	"testing"
)

func TestAddPKCSPadding(t *testing.T) {
	actual, err := AddPKCS7Padding([]byte("YELLOW SUBMARINE"), 20)
	if err != nil {
		t.Errorf("Failed to add padding: %v", err)
	}
	expected := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if !bytes.Equal(actual, []byte(expected)) {
		t.Errorf("Wrong padding: %q, expected %q", actual, expected)
	}
}
