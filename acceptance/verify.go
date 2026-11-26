package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"

	zx509 "github.com/zmap/zcrypto/x509"
)

// goVerify runs the standard library chain verifier. It returns "accept" or a
// compact "reject: <reason>". A strict parse failure of a chain member is
// reported as a rejection too.
func goVerify(rootPEM, caPEM, leafPEM []byte, dns string) string {
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(rootPEM) {
		return "reject: root parse"
	}
	caCert, err := parseStdPEM(caPEM)
	if err != nil {
		return "reject: strict CA parse: " + firstLine(err.Error())
	}
	leafCert, err := parseStdPEM(leafPEM)
	if err != nil {
		return "reject: strict leaf parse: " + firstLine(err.Error())
	}
	inter := x509.NewCertPool()
	inter.AddCert(caCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		DNSName:       dns,
		Roots:         rootPool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err == nil {
		return "accept"
	}
	return "reject: " + firstLine(err.Error())
}

func parseStdPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// zlintParse parses with the lenient zcrypto parser used by zlint.
func zlintParse(b []byte) (*zx509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return zx509.ParseCertificate(block.Bytes)
}

// opensslVerify runs `openssl verify -purpose sslserver` on the leaf through
// the scenario CA. The directory must already contain root.pem and ca.pem.
func opensslVerify(dir, leafFile string) string {
	cmd := exec.Command("openssl", "verify", "-purpose", "sslserver",
		"-CAfile", filepath.Join(dir, "root.pem"),
		"-untrusted", filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, leafFile))
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		return "accept"
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "error ") {
			return "reject: " + line
		}
	}
	return "reject: " + firstLine(text)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
