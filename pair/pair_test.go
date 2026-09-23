package pair

import (
	"testing"
)

func TestParseURIThenAttachMaterial(t *testing.T) {
	uri := "tableaux://10.0.0.1:50051?token=op&fp=AB%3ACD&serial=panel-7"
	b, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if got, want := b.Host(), "10.0.0.1"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
	if got, want := b.Port(), int32(50051); got != want {
		t.Errorf("Port = %d, want %d", got, want)
	}
	if got, want := b.Token(), "op"; got != want {
		t.Errorf("Token = %q, want %q", got, want)
	}
	if got, want := b.Fingerprint(), "AB:CD"; got != want {
		t.Errorf("Fingerprint = %q, want %q", got, want)
	}
	if got, want := b.Serial(), "panel-7"; got != want {
		t.Errorf("Serial = %q, want %q", got, want)
	}
	// TLS material is empty until we attach it.
	if b.CertPEM() != "" {
		t.Error("CertPEM should be empty before WithMaterial")
	}

	enriched := WithMaterial(b, "op-tok", "ad-tok", "CERT", "CLIENT-CERT", "CLIENT-KEY")
	if enriched.OperatorToken() != "op-tok" {
		t.Error("OperatorToken not set")
	}
	if enriched.AdminToken() != "ad-tok" {
		t.Error("AdminToken not set")
	}
	if enriched.CertPEM() != "CERT" {
		t.Error("CertPEM not set")
	}
	if enriched.ClientCertPEM() != "CLIENT-CERT" {
		t.Error("ClientCertPEM not set")
	}
	if enriched.ClientKeyPEM() != "CLIENT-KEY" {
		t.Error("ClientKeyPEM not set")
	}
	// Original is unchanged.
	if b.OperatorToken() != "" {
		t.Error("WithMaterial mutated the original")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	src := WithMaterial(
		NewBundle("h", 50051, "t", "f", "s"),
		"op", "ad", "C", "CC", "CK",
	)
	encoded := src.Encode()
	if len(encoded) == 0 {
		t.Fatal("empty encoded payload")
	}
	got, err := DecodeBundle(encoded)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"Host", got.Host(), "h"},
		{"Token", got.Token(), "t"},
		{"Fingerprint", got.Fingerprint(), "f"},
		{"Serial", got.Serial(), "s"},
		{"OperatorToken", got.OperatorToken(), "op"},
		{"AdminToken", got.AdminToken(), "ad"},
		{"CertPEM", got.CertPEM(), "C"},
		{"ClientCertPEM", got.ClientCertPEM(), "CC"},
		{"ClientKeyPEM", got.ClientKeyPEM(), "CK"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if got.Port() != 50051 {
		t.Errorf("Port = %d, want 50051", got.Port())
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := DecodeBundle(nil); err == nil {
		t.Error("expected error on nil input")
	}
	if _, err := DecodeBundle([]byte{}); err == nil {
		t.Error("expected error on empty input")
	}
}

func TestPutBundleRequiresSerial(t *testing.T) {
	// Use a fake OpenBao that would panic if called — we want the
	// validation to fail before the network round-trip.
	o := &openBaoFacade{inner: nil} // nil inner is fine if we never reach it.
	b := NewBundle("h", 50051, "t", "f", "")
	err := o.PutBundle(b)
	if err == nil {
		t.Fatal("expected error for empty serial")
	}
}

func TestGetBundleEmptySerialRejected(t *testing.T) {
	o := &openBaoFacade{inner: nil}
	if _, err := o.GetBundle(""); err == nil {
		t.Error("expected error for empty serial")
	}
	if err := o.DestroyBundle(""); err == nil {
		t.Error("expected error for empty serial")
	}
}
