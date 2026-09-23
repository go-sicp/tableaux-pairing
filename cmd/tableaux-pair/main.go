// Command tableaux-pair exercises the pairing library from a terminal,
// without going through the gomobile-bound AAR. Useful for:
//
//   - sanity-checking OpenBao reachability and the AppRole policy
//   - dry-running the QR flow during fleet enrolment
//   - copying a Bundle in and out of OpenBao without the Android UI
//
// The Android companion app calls the same pair package; this CLI is
// the workstation-side equivalent.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-sicp/tableaux-pairing/pair"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse":
		runParse(os.Args[2:])
	case "store":
		runStore(os.Args[2:])
	case "fetch":
		runFetch(os.Args[2:])
	case "destroy":
		runDestroy(os.Args[2:])
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `tableaux-pair - companion app exercise CLI

Usage:
  tableaux-pair parse   <tableaux://...>                    parse a QR URI
  tableaux-pair store   --bao-url --role-id --secret-id     store a Bundle in OpenBao
                        --serial --uri [--cert FILE
                        --client-cert FILE --client-key FILE
                        --op-token --admin-token]
  tableaux-pair fetch   --bao-url --role-id --secret-id     read a Bundle back
                        --serial
  tableaux-pair destroy --bao-url --role-id --secret-id     wipe a Bundle
                        --serial
`)
}

// ---- subcommands ----------------------------------------------------

func runParse(args []string) {
	if len(args) != 1 {
		exit("parse: expected exactly one URI argument")
	}
	b, err := pair.ParseURI(args[0])
	if err != nil {
		exit("parse: %v", err)
	}
	printBundle(b)
}

func runStore(args []string) {
	fs := flag.NewFlagSet("store", flag.ExitOnError)
	url := fs.String("bao-url", "", "OpenBao base URL")
	roleID := fs.String("role-id", "", "AppRole role_id")
	secretID := fs.String("secret-id", "", "AppRole secret_id")
	serial := fs.String("serial", "", "panel serial (used as KV path /fleet/<serial>)")
	uri := fs.String("uri", "", "tableaux:// URI from QR scan (optional)")
	certPath := fs.String("cert", "", "server cert PEM file")
	clientCertPath := fs.String("client-cert", "", "client cert PEM file")
	clientKeyPath := fs.String("client-key", "", "client key PEM file")
	opTok := fs.String("op-token", "", "operator bearer token")
	adminTok := fs.String("admin-token", "", "admin bearer token")
	_ = fs.Parse(args)

	if *url == "" || *roleID == "" || *secretID == "" || *serial == "" {
		exit("store: --bao-url, --role-id, --secret-id and --serial are required")
	}
	bao, err := pair.NewOpenBao(*url, *roleID, *secretID)
	if err != nil {
		exit("store: %v", err)
	}
	var b pair.Bundle
	if *uri != "" {
		b, err = pair.ParseURI(*uri)
		if err != nil {
			exit("store: parse uri: %v", err)
		}
	} else {
		b = pair.NewBundle("", 0, "", "", *serial)
	}
	if *serial != "" && b.Serial() != *serial {
		// Caller passed both --uri and --serial; trust --serial.
		b = pair.NewBundle(b.Host(), b.Port(), b.Token(), b.Fingerprint(), *serial)
	}
	b = pair.WithMaterial(
		b,
		*opTok,
		*adminTok,
		readFile(*certPath),
		readFile(*clientCertPath),
		readFile(*clientKeyPath),
	)
	if err := bao.PutBundle(b); err != nil {
		exit("store: PutBundle: %v", err)
	}
	fmt.Printf("stored bundle for serial=%s at fleet/%s\n", b.Serial(), b.Serial())
}

func runFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	url := fs.String("bao-url", "", "OpenBao base URL")
	roleID := fs.String("role-id", "", "AppRole role_id")
	secretID := fs.String("secret-id", "", "AppRole secret_id")
	serial := fs.String("serial", "", "panel serial")
	_ = fs.Parse(args)

	if *url == "" || *roleID == "" || *secretID == "" || *serial == "" {
		exit("fetch: --bao-url, --role-id, --secret-id and --serial are required")
	}
	bao, err := pair.NewOpenBao(*url, *roleID, *secretID)
	if err != nil {
		exit("fetch: %v", err)
	}
	b, err := bao.GetBundle(*serial)
	if err != nil {
		exit("fetch: %v", err)
	}
	printBundle(b)
}

func runDestroy(args []string) {
	fs := flag.NewFlagSet("destroy", flag.ExitOnError)
	url := fs.String("bao-url", "", "OpenBao base URL")
	roleID := fs.String("role-id", "", "AppRole role_id")
	secretID := fs.String("secret-id", "", "AppRole secret_id")
	serial := fs.String("serial", "", "panel serial")
	_ = fs.Parse(args)

	if *url == "" || *roleID == "" || *secretID == "" || *serial == "" {
		exit("destroy: --bao-url, --role-id, --secret-id and --serial are required")
	}
	bao, err := pair.NewOpenBao(*url, *roleID, *secretID)
	if err != nil {
		exit("destroy: %v", err)
	}
	if err := bao.DestroyBundle(*serial); err != nil {
		exit("destroy: %v", err)
	}
	fmt.Printf("destroyed fleet/%s\n", *serial)
}

// ---- helpers --------------------------------------------------------

func printBundle(b pair.Bundle) {
	fmt.Printf("host:            %s\n", b.Host())
	fmt.Printf("port:            %d\n", b.Port())
	fmt.Printf("serial:          %s\n", b.Serial())
	fmt.Printf("fingerprint:     %s\n", b.Fingerprint())
	fmt.Printf("token (qr):      %s\n", abbrev(b.Token()))
	fmt.Printf("operator_token:  %s\n", abbrev(b.OperatorToken()))
	fmt.Printf("admin_token:     %s\n", abbrev(b.AdminToken()))
	fmt.Printf("cert_pem:        %s\n", abbrev(b.CertPEM()))
	fmt.Printf("client_cert_pem: %s\n", abbrev(b.ClientCertPEM()))
	fmt.Printf("client_key_pem:  %s\n", abbrev(b.ClientKeyPEM()))
}

func abbrev(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "..." + s[len(s)-8:]
}

func readFile(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		exit("read %s: %v", path, err)
	}
	return string(b)
}

func exit(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
