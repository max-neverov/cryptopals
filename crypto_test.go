package cryptopals

import (
	"bytes"
	"strings"
	"testing"
)

func TestToBase64(t *testing.T) {
	base64Tests := []struct {
		in       string // input
		expected string // expected result
	}{
		{"4d616e", "TWFu"},
		{"4d61", "TWE="},
		{"4d", "TQ=="},
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
	}
	for _, tt := range base64Tests {
		actual, err := ToBase64String(strings.NewReader(tt.in))
		if err != nil {
			t.Errorf("Error while converting [%q]: %v", tt.in, err)
		}

		if actual != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, actual)
		}
	}
}

func TestFixedXor(t *testing.T) {
	l := strings.NewReader("1c0111001f010100061a024b53535009181c")
	r := strings.NewReader("686974207468652062756c6c277320657965")
	actual, err := FixedXor(l, r)
	if err != nil {
		t.Errorf("Error while %q xor %q: %v", l, r, err)
	}
	expected := []byte("746865206b696420646f6e277420706c6179")
	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %q, got %q", expected, actual)
	}
}
