package main

import (
	stdx509 "crypto/x509"
)

// Browser reason labels. These are the user-visible / net-error codes that
// Chromium and NSS/Firefox map the corresponding verification failure to.
const (
	chromeInvalid = "NET::ERR_CERT_INVALID (-207)"
	chromeNC      = "NET::ERR_CERT_NAME_CONSTRAINT_VIOLATION (-212)"
	chromeSSLKU   = "net::ERR_SSL_KEY_USAGE_INCOMPATIBLE"
	ffKU          = "SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)"
	ffNameSpace   = "SEC_ERROR_CERT_NOT_IN_NAME_SPACE"
	ffExtValue    = "SEC_ERROR_EXTENSION_VALUE_INVALID"
	browserOK     = "accept (no browser rejection)"
)

type scenario struct {
	n        int
	id       string
	title    string
	category string
	target   string // "ca" or "leaf"

	lint     string
	severity string // error | warn | info

	chrome  string
	firefox string

	browserReject bool
	// Independent oracle expectations (chain verification of the leaf).
	expectOpenSSLReject bool
	expectGoReject      bool

	dns  string
	ca   certSpec
	leaf certSpec
}

const defaultDNS = "app.internal.example"

func scenarios() []scenario {
	var out []scenario
	add := func(s scenario) {
		s.n = len(out) + 1
		out = append(out, s)
	}

	// ---------------------------------------------------------------------
	// Extension ordering (5) — informational only, chains stay valid.
	// ---------------------------------------------------------------------
	orderLint := "n_internal_ca_ext_order_noncanonical"
	orderPerms := [][]string{
		{"ku", "bc", "eku", "nc", "ski", "aki", "san"},
		{"bc", "eku", "ku", "nc", "ski", "aki", "san"},
		{"bc", "ku", "eku", "nc", "san", "ski", "aki"},
		{"bc", "ku", "eku", "nc", "aki", "ski", "san"},
		{"bc", "ku", "ski", "eku", "aki", "san", "nc"},
	}
	orderTitles := []string{
		"keyUsage encoded before basicConstraints",
		"extKeyUsage encoded before keyUsage",
		"subjectAltName encoded before subjectKeyIdentifier/AKI",
		"authorityKeyIdentifier encoded before subjectKeyIdentifier",
		"subjectKeyIdentifier encoded before extKeyUsage",
	}
	for i, perm := range orderPerms {
		leaf := goodLeafSpec("order-leaf", defaultDNS)
		leaf.order = perm
		add(scenario{
			id: "ext-order-" + string(rune('a'+i)), title: orderTitles[i], category: "extension_order",
			target: "leaf", lint: orderLint, severity: "info",
			chrome: browserOK, firefox: browserOK, browserReject: false,
			dns: defaultDNS, ca: goodCASpec("order-ca"), leaf: leaf,
		})
	}

	// ---------------------------------------------------------------------
	// KeyUsage: CA cannot sign (4) — Error, chains rejected everywhere.
	// ---------------------------------------------------------------------
	caNoSignLint := "e_internal_ca_ku_ca_missing_certsign"
	caBadKUs := []stdx509.KeyUsage{
		stdx509.KeyUsageCRLSign,
		stdx509.KeyUsageDigitalSignature,
		stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageCRLSign,
		stdx509.KeyUsageContentCommitment | stdx509.KeyUsageCRLSign,
	}
	for i, ku := range caBadKUs {
		ca := goodCASpec("bad-ku-ca")
		ca.ku = ku
		add(scenario{
			id:    "ca-no-certsign-" + string(rune('a'+i)),
			title: "CA basicConstraints=CA:TRUE but keyUsage lacks keyCertSign", category: "key_usage",
			target: "ca", lint: caNoSignLint, severity: "error",
			chrome: chromeInvalid, firefox: ffKU, browserReject: true,
			expectOpenSSLReject: true, expectGoReject: true,
			dns: defaultDNS, ca: ca, leaf: goodLeafSpec("after-bad-ca", defaultDNS),
		})
	}

	// ---------------------------------------------------------------------
	// KeyUsage: TLS leaf with no operable bit (5) — Error; OpenSSL/Firefox
	// reject the purpose while Go intentionally ignores KU bits.
	// ---------------------------------------------------------------------
	leafUnusableLint := "e_internal_ca_ku_tls_leaf_unusable"
	leafBadKUs := []stdx509.KeyUsage{
		stdx509.KeyUsageContentCommitment,
		stdx509.KeyUsageCertSign,
		stdx509.KeyUsageCRLSign,
		stdx509.KeyUsageDataEncipherment,
		stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	}
	leafBadTitles := []string{
		"TLS leaf keyUsage is contentCommitment only",
		"TLS leaf keyUsage asserts keyCertSign only",
		"TLS leaf keyUsage asserts cRLSign only",
		"TLS leaf keyUsage is dataEncipherment only",
		"TLS leaf keyUsage carries CA sign bits but no TLS operation bit",
	}
	for i, ku := range leafBadKUs {
		leaf := goodLeafSpec("bad-ku-leaf", defaultDNS)
		leaf.ku = ku
		add(scenario{
			id: "leaf-ku-unusable-" + string(rune('a'+i)), title: leafBadTitles[i], category: "key_usage",
			target: "leaf", lint: leafUnusableLint, severity: "error",
			chrome: chromeSSLKU, firefox: ffKU, browserReject: true,
			expectOpenSSLReject: true, expectGoReject: false,
			dns: defaultDNS, ca: goodCASpec("leaf-ku-ca"), leaf: leaf,
		})
	}

	// ---------------------------------------------------------------------
	// KeyUsage: encipherOnly/decipherOnly without keyAgreement (4) — Warn,
	// chains still validate because an operable bit is retained.
	// ---------------------------------------------------------------------
	orphanLint := "w_internal_ca_ku_agreement_bits_orphan"
	orphanKUs := []stdx509.KeyUsage{
		stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageEncipherOnly,
		stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageDecipherOnly,
		stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageKeyEncipherment | stdx509.KeyUsageEncipherOnly,
		stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageEncipherOnly | stdx509.KeyUsageDecipherOnly,
	}
	for i, ku := range orphanKUs {
		leaf := goodLeafSpec("orphan-ku-leaf", defaultDNS)
		leaf.ku = ku
		add(scenario{
			id:    "ku-orphan-bit-" + string(rune('a'+i)),
			title: "encipherOnly/decipherOnly asserted without keyAgreement", category: "key_usage",
			target: "leaf", lint: orphanLint, severity: "warn",
			chrome: browserOK, firefox: browserOK, browserReject: false,
			dns: defaultDNS, ca: goodCASpec("orphan-ku-ca"), leaf: leaf,
		})
	}

	// ---------------------------------------------------------------------
	// KeyUsage: over-privileged CA combination (3) — Notice, still valid.
	// ---------------------------------------------------------------------
	nonminimalLint := "n_internal_ca_ku_ca_nonminimal"
	nonminimalKUs := []stdx509.KeyUsage{
		stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign | stdx509.KeyUsageKeyEncipherment,
		stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign | stdx509.KeyUsageDataEncipherment,
		stdx509.KeyUsageCertSign | stdx509.KeyUsageKeyEncipherment | stdx509.KeyUsageDataEncipherment,
	}
	for i, ku := range nonminimalKUs {
		ca := goodCASpec("nonminimal-ca")
		ca.ku = ku
		add(scenario{
			id:    "ca-ku-nonminimal-" + string(rune('a'+i)),
			title: "CA keyUsage mixes keyCertSign with data-plane encipherment bits", category: "key_usage",
			target: "ca", lint: nonminimalLint, severity: "info",
			chrome: browserOK, firefox: browserOK, browserReject: false,
			dns: defaultDNS, ca: ca, leaf: goodLeafSpec("nonminimal-leaf", defaultDNS),
		})
	}

	// ---------------------------------------------------------------------
	// Name constraints: malformed DNS syntax (4) — Error, strict parsers and
	// chain validators reject.
	// ---------------------------------------------------------------------
	ncSyntaxLint := "e_internal_ca_nc_dns_syntax"
	malformed := []string{"example..internal", "bad name.internal", "invalid!.internal", ".leadingdot.internal"}
	for i, bad := range malformed {
		ca := goodCASpec("nc-syntax-ca")
		ca.ncPresent = true
		ca.ncCritical = true
		ca.ncPermitted = []string{bad}
		add(scenario{
			id:    "nc-dns-syntax-" + string(rune('a'+i)),
			title: "permitted name constraint is not valid DNS syntax (" + bad + ")", category: "name_constraints",
			target: "ca", lint: ncSyntaxLint, severity: "error",
			chrome: chromeInvalid, firefox: ffExtValue, browserReject: true,
			expectOpenSSLReject: true, expectGoReject: true,
			dns: "app.good.internal", ca: ca, leaf: goodLeafSpec("nc-syntax-leaf", "app.good.internal"),
		})
	}

	// ---------------------------------------------------------------------
	// Name constraints: too broad (3) — Warn, chains remain valid.
	// ---------------------------------------------------------------------
	ncBroadLint := "w_internal_ca_nc_dns_too_broad"
	broad := []struct{ base, host string }{
		{"test", "app.test"},
		{"internal", "wiki.internal"},
		{"local", "printer01.office.local"},
	}
	for i, b := range broad {
		ca := goodCASpec("nc-broad-ca")
		ca.ncPresent = true
		ca.ncCritical = true
		ca.ncPermitted = []string{b.base}
		add(scenario{
			id:    "nc-dns-broad-" + string(rune('a'+i)),
			title: "permitted name constraint scopes whole single-label namespace \"" + b.base + "\"", category: "name_constraints",
			target: "ca", lint: ncBroadLint, severity: "warn",
			chrome: browserOK, firefox: browserOK, browserReject: false,
			dns: b.host, ca: ca, leaf: goodLeafSpec("nc-broad-leaf", b.host),
		})
	}

	// ---------------------------------------------------------------------
	// Name constraints: redundant permitted entries (2) — Notice, valid.
	// ---------------------------------------------------------------------
	ncRedundantLint := "n_internal_ca_nc_dns_redundant"
	redundant := []struct {
		permitted []string
		host      string
	}{
		{[]string{"example.internal", "www.example.internal"}, "app.example.internal"},
		{[]string{"corp.internal", "a.corp.internal"}, "b.corp.internal"},
	}
	for i, r := range redundant {
		ca := goodCASpec("nc-redundant-ca")
		ca.ncPresent = true
		ca.ncCritical = true
		ca.ncPermitted = r.permitted
		add(scenario{
			id:    "nc-dns-redundant-" + string(rune('a'+i)),
			title: "one permitted constraint is already covered by a broader permitted constraint", category: "name_constraints",
			target: "ca", lint: ncRedundantLint, severity: "info",
			chrome: browserOK, firefox: browserOK, browserReject: false,
			dns: r.host, ca: ca, leaf: goodLeafSpec("nc-redundant-leaf", r.host),
		})
	}

	return out
}
