package connecturi

import (
	"strings"
	"testing"
)

func TestParseHappyPath(t *testing.T) {
	uri := "tableaux://192.168.1.42:50051?token=abc123&fp=AB%3ACD%3AEF%3A01"
	p, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := p.Host(), "192.168.1.42"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
	if got, want := p.Port(), 50051; got != want {
		t.Errorf("Port = %d, want %d", got, want)
	}
	if got, want := p.Token(), "abc123"; got != want {
		t.Errorf("Token = %q, want %q", got, want)
	}
	if got, want := p.ServerFingerprint(), "AB:CD:EF:01"; got != want {
		t.Errorf("ServerFingerprint = %q, want %q", got, want)
	}
	if got := p.Serial(); got != "" {
		t.Errorf("Serial = %q, want empty", got)
	}
}

func TestParseSerialIsOptional(t *testing.T) {
	uri := "tableaux://10.0.0.1:50051?token=t&fp=F&serial=panel-7"
	p, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := p.Serial(), "panel-7"; got != want {
		t.Errorf("Serial = %q, want %q", got, want)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
	}{
		{"wrong scheme", "https://1.2.3.4:50051?token=t&fp=f", "scheme"},
		{"no port", "tableaux://1.2.3.4?token=t&fp=f", "host:port"},
		{"port out of range", "tableaux://1.2.3.4:99999?token=t&fp=f", "invalid port"},
		{"missing token", "tableaux://1.2.3.4:50051?fp=f", "missing token"},
		{"missing fp", "tableaux://1.2.3.4:50051?token=t", "missing fp"},
		{"empty authority", "tableaux://?token=t&fp=f", "authority"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.uri)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestBuildRoundTrip(t *testing.T) {
	uri := Build("10.0.0.1", 50051, "tok with spaces & symbols", "AB:CD", "panel-3")
	if !strings.HasPrefix(uri, "tableaux://10.0.0.1:50051?") {
		t.Fatalf("unexpected prefix: %q", uri)
	}
	p, err := Parse(uri)
	if err != nil {
		t.Fatalf("round-trip Parse: %v", err)
	}
	if p.Token() != "tok with spaces & symbols" {
		t.Errorf("token mangled: %q", p.Token())
	}
	if p.ServerFingerprint() != "AB:CD" {
		t.Errorf("fp mangled: %q", p.ServerFingerprint())
	}
	if p.Serial() != "panel-3" {
		t.Errorf("serial mangled: %q", p.Serial())
	}
}

func TestBuildOmitsEmptySerial(t *testing.T) {
	uri := Build("h", 1, "t", "f", "")
	if strings.Contains(uri, "serial=") {
		t.Errorf("URI should not carry empty serial: %q", uri)
	}
}
