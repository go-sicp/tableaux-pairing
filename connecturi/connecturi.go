// Package connecturi parses and builds the tableaux:// URI shown in the
// QR code by a running tableaux-eink server.
//
// On-the-wire shape:
//
//	tableaux://<host>:<port>?token=<bearer>&fp=<sha256>&serial=<panel-id>
//
// Only host, port, token and fp are required; serial is optional but
// recommended (lets the companion app look up the matching secret in
// OpenBao at secret/fleet/<serial>).
//
// The Kotlin side equivalent is io.github.tableaux.eink.grpc.qr.ConnectUri.
package connecturi

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Scheme is the URI scheme reserved for fleet pairing.
const Scheme = "tableaux"

// Parsed exposes the components of a tableaux:// URI. Fields are
// unexported on the underlying struct; access is via methods so the
// public surface stays stable across versions.
type Parsed interface {
	Host() string
	Port() int
	Token() string
	ServerFingerprint() string
	Serial() string
}

// Parse parses a tableaux:// URI. Returns an error if the scheme,
// authority or required query parameters are missing.
func Parse(rawURI string) (Parsed, error) {
	if !strings.HasPrefix(rawURI, Scheme+"://") {
		return nil, fmt.Errorf("connecturi: missing %q scheme", Scheme)
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("connecturi: parse: %w", err)
	}
	if u.Scheme != Scheme {
		return nil, fmt.Errorf("connecturi: scheme %q, want %q", u.Scheme, Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("connecturi: missing authority")
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return nil, fmt.Errorf("connecturi: authority %q must be host:port", u.Host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("connecturi: invalid port %q", portStr)
	}
	q := u.Query()
	token := q.Get("token")
	fp := q.Get("fp")
	if token == "" {
		return nil, errors.New("connecturi: missing token query parameter")
	}
	if fp == "" {
		return nil, errors.New("connecturi: missing fp query parameter")
	}
	return &parsed{
		host:   host,
		port:   port,
		token:  token,
		fp:     fp,
		serial: q.Get("serial"),
	}, nil
}

// Build constructs a tableaux:// URI from its components. The serial
// argument may be empty to omit it.
func Build(host string, port int, token, fingerprint, serial string) string {
	q := url.Values{}
	q.Set("token", token)
	q.Set("fp", fingerprint)
	if serial != "" {
		q.Set("serial", serial)
	}
	u := url.URL{
		Scheme:   Scheme,
		Host:     fmt.Sprintf("%s:%d", host, port),
		RawQuery: q.Encode(),
	}
	return u.String()
}

type parsed struct {
	host   string
	port   int
	token  string
	fp     string
	serial string
}

func (p *parsed) Host() string              { return p.host }
func (p *parsed) Port() int                 { return p.port }
func (p *parsed) Token() string             { return p.token }
func (p *parsed) ServerFingerprint() string { return p.fp }
func (p *parsed) Serial() string            { return p.serial }
