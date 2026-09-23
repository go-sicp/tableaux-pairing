// Package pair is the gomobile-bind-friendly facade exposed to the
// Android companion app. It hides the connecturi/openbao subpackages
// behind a small set of interfaces and constructors that survive the
// gomobile bind type-system restrictions:
//
//   - no maps in public signatures
//   - no slices of struct in public signatures
//   - no context.Context in public signatures
//   - returns at most (T, error)
//
// Build with:
//
//	gomobile bind \
//	  -target=android \
//	  -androidapi 26 \
//	  -o tableaux-pairing.aar \
//	  ./pair
//
// Then drop tableaux-pairing.aar into the Android app's libs/ folder.
package pair

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-sicp/tableaux-pairing/connecturi"
	"github.com/go-sicp/tableaux-pairing/openbao"
)

// Bundle is everything the companion app moves between the display, the
// QR code, and OpenBao. Fields are unexported on the impl; access is
// through methods so the binding contract is stable.
type Bundle interface {
	Host() string
	Port() int32
	Token() string
	Fingerprint() string
	Serial() string

	OperatorToken() string
	AdminToken() string
	CertPEM() string
	ClientCertPEM() string
	ClientKeyPEM() string

	// Encode returns a JSON byte representation suitable for any
	// short-lived transport (clipboard, in-memory hand-off between
	// activities, persistent cache). DecodeBundle is the inverse.
	Encode() []byte
}

// NewBundle constructs a Bundle carrying only the QR-derived fields
// (no TLS material yet). Use [WithMaterial] to attach cert / key PEMs
// before pushing to OpenBao.
func NewBundle(host string, port int32, token, fingerprint, serial string) Bundle {
	return &bundle{
		host:        host,
		port:        port,
		token:       token,
		fingerprint: fingerprint,
		serial:      serial,
	}
}

// WithMaterial returns a copy of [b] with the cert / key / token
// material attached. The original is unchanged.
func WithMaterial(
	b Bundle,
	operator, admin, certPEM, clientCertPEM, clientKeyPEM string,
) Bundle {
	src, ok := b.(*bundle)
	if !ok {
		return b
	}
	out := *src
	out.operator = operator
	out.admin = admin
	out.certPEM = certPEM
	out.clientCertPEM = clientCertPEM
	out.clientKeyPEM = clientKeyPEM
	return &out
}

// ParseURI accepts a tableaux:// URI (typically scanned from a QR) and
// returns the Bundle skeleton. TLS material is left empty; fetch it
// separately from OpenBao.
func ParseURI(uri string) (Bundle, error) {
	p, err := connecturi.Parse(uri)
	if err != nil {
		return nil, err
	}
	return &bundle{
		host:        p.Host(),
		port:        int32(p.Port()),
		token:       p.Token(),
		fingerprint: p.ServerFingerprint(),
		serial:      p.Serial(),
	}, nil
}

// DecodeBundle reverses [Bundle.Encode]. Used by callers that hold a
// previously serialised Bundle (clipboard, intermediate cache, restored
// activity state).
func DecodeBundle(data []byte) (Bundle, error) {
	if len(data) == 0 {
		return nil, errors.New("pair: empty bundle bytes")
	}
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// OpenBao is the Bundle-aware persistence layer. Wraps openbao.Client
// to map a serial -> KV path and Bundle <-> KV map.
type OpenBao interface {
	// PutBundle stores b at secret/fleet/<b.Serial()>.
	PutBundle(b Bundle) error

	// GetBundle reads back a Bundle stored at secret/fleet/<serial>.
	GetBundle(serial string) (Bundle, error)

	// DestroyBundle wipes secret/fleet/<serial>.
	DestroyBundle(serial string) error

	// Login forces an AppRole login now (otherwise login is lazy on
	// first Put/Get).
	Login() error
}

// NewOpenBao constructs an OpenBao client with AppRole credentials.
func NewOpenBao(baseURL, roleID, secretID string) (OpenBao, error) {
	c, err := openbao.New(openbao.Config{
		BaseURL:  baseURL,
		RoleID:   roleID,
		SecretID: secretID,
	})
	if err != nil {
		return nil, err
	}
	return &openBaoFacade{inner: c, timeout: 10 * time.Second}, nil
}

// ---- internals ------------------------------------------------------

type bundle struct {
	host        string
	port        int32
	token       string
	fingerprint string
	serial      string

	operator      string
	admin         string
	certPEM       string
	clientCertPEM string
	clientKeyPEM  string
}

func (b *bundle) Host() string          { return b.host }
func (b *bundle) Port() int32           { return b.port }
func (b *bundle) Token() string         { return b.token }
func (b *bundle) Fingerprint() string   { return b.fingerprint }
func (b *bundle) Serial() string        { return b.serial }
func (b *bundle) OperatorToken() string { return b.operator }
func (b *bundle) AdminToken() string    { return b.admin }
func (b *bundle) CertPEM() string       { return b.certPEM }
func (b *bundle) ClientCertPEM() string { return b.clientCertPEM }
func (b *bundle) ClientKeyPEM() string  { return b.clientKeyPEM }

// MarshalJSON / UnmarshalJSON give Encode/Decode a stable wire shape
// independent of the unexported field names.
type bundleWire struct {
	Host        string `json:"host"`
	Port        int32  `json:"port"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	Serial      string `json:"serial,omitempty"`

	Operator      string `json:"operator_token,omitempty"`
	Admin         string `json:"admin_token,omitempty"`
	CertPEM       string `json:"cert_pem,omitempty"`
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string `json:"client_key_pem,omitempty"`
}

func (b *bundle) MarshalJSON() ([]byte, error) {
	return json.Marshal(bundleWire{
		Host:          b.host,
		Port:          b.port,
		Token:         b.token,
		Fingerprint:   b.fingerprint,
		Serial:        b.serial,
		Operator:      b.operator,
		Admin:         b.admin,
		CertPEM:       b.certPEM,
		ClientCertPEM: b.clientCertPEM,
		ClientKeyPEM:  b.clientKeyPEM,
	})
}

func (b *bundle) UnmarshalJSON(data []byte) error {
	var w bundleWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	b.host = w.Host
	b.port = w.Port
	b.token = w.Token
	b.fingerprint = w.Fingerprint
	b.serial = w.Serial
	b.operator = w.Operator
	b.admin = w.Admin
	b.certPEM = w.CertPEM
	b.clientCertPEM = w.ClientCertPEM
	b.clientKeyPEM = w.ClientKeyPEM
	return nil
}

func (b *bundle) Encode() []byte {
	out, _ := json.Marshal(b)
	return out
}

type openBaoFacade struct {
	inner   openbao.Client
	timeout time.Duration
}

func (o *openBaoFacade) Login() error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	return o.inner.Login(ctx)
}

func (o *openBaoFacade) PutBundle(b Bundle) error {
	if b.Serial() == "" {
		return errors.New("pair: bundle has empty serial; cannot derive OpenBao path")
	}
	data := map[string]string{
		"host":            b.Host(),
		"port":            int32String(b.Port()),
		"token":           b.Token(),
		"fingerprint":     b.Fingerprint(),
		"operator_token":  b.OperatorToken(),
		"admin_token":     b.AdminToken(),
		"cert_pem":        b.CertPEM(),
		"client_cert_pem": b.ClientCertPEM(),
		"client_key_pem":  b.ClientKeyPEM(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	return o.inner.PutSecret(ctx, "fleet/"+b.Serial(), data)
}

func (o *openBaoFacade) GetBundle(serial string) (Bundle, error) {
	if serial == "" {
		return nil, errors.New("pair: empty serial")
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	data, err := o.inner.GetSecret(ctx, "fleet/"+serial)
	if err != nil {
		return nil, err
	}
	port, _ := stringInt32(data["port"])
	return &bundle{
		host:          data["host"],
		port:          port,
		token:         data["token"],
		fingerprint:   data["fingerprint"],
		serial:        serial,
		operator:      data["operator_token"],
		admin:         data["admin_token"],
		certPEM:       data["cert_pem"],
		clientCertPEM: data["client_cert_pem"],
		clientKeyPEM:  data["client_key_pem"],
	}, nil
}

func (o *openBaoFacade) DestroyBundle(serial string) error {
	if serial == "" {
		return errors.New("pair: empty serial")
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	return o.inner.DestroySecret(ctx, "fleet/"+serial)
}

func int32String(n int32) string {
	// Allocation-free for the small values we deal with (port range).
	return jsonNumber(n)
}

func stringInt32(s string) (int32, error) {
	if s == "" {
		return 0, nil
	}
	n, err := jsonParseInt32(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Tiny helpers using encoding/json to avoid pulling strconv into a
// signature gomobile would have to bridge for. Slightly slower than
// strconv but irrelevant on a port number.
func jsonNumber(n int32) string {
	out, _ := json.Marshal(n)
	return string(out)
}

func jsonParseInt32(s string) (int32, error) {
	var n int32
	err := json.Unmarshal([]byte(s), &n)
	return n, err
}
