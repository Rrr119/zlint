package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"time"
)

// keyRand makes the throwaway acceptance keys reproducible across runs so that
// the Chromium SPKI pins used by browser/probe.mjs stay stable. This is only a
// test-corpus generator; production CAs must use crypto/rand.Reader.
var keyRand = mrand.New(mrand.NewSource(0x1CA2026))

// Canonical extension keys in the internal CA profile order.
var canonicalOrder = []string{"bc", "ku", "eku", "nc", "ski", "aki", "san"}

var extOIDByKey = map[string]asn1.ObjectIdentifier{
	"bc":  {2, 5, 29, 19},
	"ku":  {2, 5, 29, 15},
	"eku": {2, 5, 29, 37},
	"nc":  {2, 5, 29, 30},
	"ski": {2, 5, 29, 14},
	"aki": {2, 5, 29, 35},
	"san": {2, 5, 29, 17},
}

func extBC(isCA bool) pkix.Extension {
	type basicConstraints struct {
		IsCA bool `asn1:"optional"`
	}
	v, _ := asn1.Marshal(basicConstraints{IsCA: isCA})
	return pkix.Extension{Id: extOIDByKey["bc"], Critical: true, Value: v}
}

func extKU(mask stdx509.KeyUsage, critical bool) pkix.Extension {
	highest := 0
	for i := 0; i <= 8; i++ {
		if mask&(1<<i) != 0 {
			highest = i
		}
	}
	nbytes := highest/8 + 1
	b := make([]byte, nbytes)
	for i := 0; i <= highest; i++ {
		if mask&(1<<i) != 0 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	v, _ := asn1.Marshal(asn1.BitString{Bytes: b, BitLength: highest + 1})
	return pkix.Extension{Id: extOIDByKey["ku"], Critical: critical, Value: v}
}

func extEKUServerAuth() pkix.Extension {
	// extKeyUsage ::= SEQUENCE OF OBJECT IDENTIFIER
	v, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	return pkix.Extension{Id: extOIDByKey["eku"], Value: v}
}

func extSKI(id []byte) pkix.Extension {
	v, _ := asn1.Marshal(id)
	return pkix.Extension{Id: extOIDByKey["ski"], Value: v}
}

type authKeyID struct {
	ID []byte `asn1:"tag:0,optional"`
}

func extAKI(id []byte) pkix.Extension {
	v, _ := asn1.Marshal(authKeyID{ID: id})
	return pkix.Extension{Id: extOIDByKey["aki"], Value: v}
}

func extSAN(dnsNames []string) pkix.Extension {
	var rawValues []asn1.RawValue
	for _, d := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2, // dNSName [2] IA5String
			Bytes: []byte(d),
		})
	}
	v, _ := asn1.Marshal(rawValues)
	return pkix.Extension{Id: extOIDByKey["san"], Value: v}
}

type ncSubtree struct {
	Base asn1.RawValue
}

type nameConstraintsRaw struct {
	Permitted []ncSubtree `asn1:"tag:0,optional"`
	Excluded  []ncSubtree `asn1:"tag:1,optional"`
}

func extNC(permitted, excluded []string, critical bool) pkix.Extension {
	nc := nameConstraintsRaw{}
	for _, d := range permitted {
		nc.Permitted = append(nc.Permitted, ncSubtree{Base: asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(d)}})
	}
	for _, d := range excluded {
		nc.Excluded = append(nc.Excluded, ncSubtree{Base: asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(d)}})
	}
	v, _ := asn1.Marshal(nc)
	return pkix.Extension{Id: extOIDByKey["nc"], Critical: critical, Value: v}
}

// certSpec fully describes one generated certificate. Every extension is built
// raw and arranged in Order, giving tests exact control over encoding order
// and unusual keyUsage/nameConstraint combinations.
type certSpec struct {
	commonName string
	isCA       bool

	ku         stdx509.KeyUsage
	kuPresent  bool
	kuCritical bool

	serverEKU bool
	dnsNames  []string

	ncPermitted []string
	ncExcluded  []string
	ncPresent   bool
	ncCritical  bool

	// order is the explicit extension key sequence. When nil, canonicalOrder
	// restricted to the present extensions is used.
	order []string
}

type builtCert struct {
	spec certSpec
	key  *ecdsa.PrivateKey
	der  []byte
	pem  []byte
	ski  []byte
	subj pkix.Name
}

func (s certSpec) serialSeed() string { return s.commonName }

func buildCert(spec certSpec, parent *builtCert) (*builtCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), keyRand)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}

	// Deterministic-ish SKI: 20 random bytes are fine, uniqueness is all that
	// matters for chaining.
	ski := make([]byte, 20)
	if _, err := rand.Read(ski); err != nil {
		return nil, err
	}

	exts := map[string]pkix.Extension{
		"bc":  extBC(spec.isCA),
		"ski": extSKI(ski),
	}
	if spec.kuPresent {
		exts["ku"] = extKU(spec.ku, spec.kuCritical)
	}
	if spec.serverEKU {
		exts["eku"] = extEKUServerAuth()
	}
	if spec.ncPresent {
		exts["nc"] = extNC(spec.ncPermitted, spec.ncExcluded, spec.ncCritical)
	}
	if len(spec.dnsNames) > 0 {
		exts["san"] = extSAN(spec.dnsNames)
	}
	if parent != nil {
		exts["aki"] = extAKI(parent.ski)
	} else {
		exts["aki"] = extAKI(ski)
	}

	order := spec.order
	if order == nil {
		order = canonicalOrder
	}
	var ordered []pkix.Extension
	for _, k := range order {
		if e, ok := exts[k]; ok {
			ordered = append(ordered, e)
		}
	}
	// Include any present extension that an explicit order omitted? No: an
	// explicit order is authoritative and omitting a key is a mistake, so make
	// it loud rather than silently appending.
	if spec.order != nil && len(ordered) != len(exts) {
		return nil, fmt.Errorf("scenario %q order %v does not cover all %d extensions", spec.commonName, spec.order, len(exts))
	}

	tmpl := &stdx509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.commonName, Organization: []string{"Internal CA Acceptance"}},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  spec.isCA,
		ExtraExtensions:       ordered,
	}

	var parentTmpl *stdx509.Certificate
	var parentKey *ecdsa.PrivateKey
	if parent == nil {
		parentTmpl = tmpl
		parentKey = key
	} else {
		// CreateCertificate reads the parent subject/SKI. Reuse the exact
		// Subject that was encoded into the parent so issuer DN matches; this
		// stays usable even when the parent DER uses constructs that the strict
		// stdlib certificate parser rejects.
		parentTmpl = &stdx509.Certificate{
			Subject:      parent.subj,
			SubjectKeyId: parent.ski,
		}
		parentKey = parent.key
	}

	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, parentTmpl, &key.PublicKey, parentKey)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate %s: %w", spec.commonName, err)
	}
	return &builtCert{
		spec: spec,
		key:  key,
		der:  der,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		ski:  ski,
		subj: tmpl.Subject,
	}, nil
}

func goodRootSpec() certSpec {
	return certSpec{
		commonName: "Internal Acceptance Root CA",
		isCA:       true,
		kuPresent:  true,
		kuCritical: true,
		ku:         stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	}
}

func goodCASpec(cn string) certSpec {
	return certSpec{
		commonName: cn,
		isCA:       true,
		kuPresent:  true,
		kuCritical: true,
		ku:         stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	}
}

func goodLeafSpec(cn, dns string) certSpec {
	return certSpec{
		commonName: cn,
		isCA:       false,
		kuPresent:  true,
		kuCritical: true,
		ku:         stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageKeyEncipherment,
		serverEKU:  true,
		dnsNames:   []string{dns},
	}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func leafKeyPEM(key *ecdsa.PrivateKey) []byte {
	der, err := stdx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
