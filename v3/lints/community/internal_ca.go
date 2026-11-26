/*
 * ZLint Copyright 2026 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package community

import (
	"strings"

	"github.com/zmap/zlint/v3/util"
)

// This file contains the shared profile data and helper routines for the
// "internal_ca" family of community lints. These lints encode the operational
// practice of a private / internal certification authority rather than a
// public CA/Browser Forum requirement. In particular they help internal PKI
// teams catch the three classes of self-signed-CA defects that most often make
// it into browser rejection reports:
//
//   - extensions encoded in an unexpected order,
//   - incoherent keyUsage bit combinations for the certificate's role, and
//   - name constraints that are malformed, too broad, or redundant.
//
// Extension order is semantically irrelevant to X.509 validation (the
// extensions field is a SEQUENCE OF and each extension is identified by OID),
// so the ordering check is intentionally only a Notice. The order below is the
// canonical profile order recommended for internal CAs; it closely matches the
// order produced by common enterprise PKI tooling.
var icaCanonicalExtOrder = []struct {
	oid  string
	name string
}{
	{util.BasicConstOID.String(), "basicConstraints"},
	{util.KeyUsageOID.String(), "keyUsage"},
	{util.EkuSynOid.String(), "extKeyUsage"},
	{util.NameConstOID.String(), "nameConstraints"},
	{util.SubjectKeyIdentityOID.String(), "subjectKeyIdentifier"},
	{util.AuthkeyOID.String(), "authorityKeyIdentifier"},
	{util.SubjectAlternateNameOID.String(), "subjectAltName"},
	{util.IssuerAlternateNameOID.String(), "issuerAltName"},
	{util.CertPolicyOID.String(), "certificatePolicies"},
	{util.CrlDistOID.String(), "cRLDistributionPoints"},
	{util.AiaOID.String(), "authorityInfoAccess"},
}

// icaExtRank maps an extension OID to its position in the canonical internal
// CA profile order. Unknown extensions have rank -1 and are ignored by the
// ordering lint.
var icaExtRank = func() map[string]int {
	m := make(map[string]int, len(icaCanonicalExtOrder))
	for i, ext := range icaCanonicalExtOrder {
		m[ext.oid] = i
	}
	return m
}()

func icaExtName(oid string) string {
	for _, ext := range icaCanonicalExtOrder {
		if ext.oid == oid {
			return ext.name
		}
	}
	return oid
}

// icaRankSequence converts encoded extension OIDs into the ranks of the
// profile-known extensions, preserving encoded order. Unknown OIDs are
// skipped. Duplicate OIDs are passed through; duplicate extensions are
// handled by e_ext_duplicate_extension.
func icaRankSequence(oids []string) []struct {
	rank int
	name string
} {
	var ordered []struct {
		rank int
		name string
	}
	for _, oid := range oids {
		if rank, ok := icaExtRank[oid]; ok {
			ordered = append(ordered, struct {
				rank int
				name string
			}{rank: rank, name: icaExtName(oid)})
		}
	}
	return ordered
}

// icaNormalizeDomain lower-cases and removes a single trailing root dot from a
// DNS-style name or name constraint.
func icaNormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

// icaDomainLabels splits a normalized domain into its labels. An empty string
// yields nil.
func icaDomainLabels(d string) []string {
	d = icaNormalizeDomain(d)
	if d == "" {
		return nil
	}
	return strings.Split(d, ".")
}

// icaValidDNSConstraint reports whether a name-constraint DNS base is
// syntactically usable. The bool return is false together with a short reason
// when the constraint is malformed. It deliberately accepts underscores and
// single-label names because both are common in split-horizon internal DNS;
// broadness is assessed separately by w_internal_ca_nc_dns_too_broad.
func icaValidDNSConstraint(constraint string) (bool, string) {
	raw := strings.TrimSpace(constraint)
	if raw == "" {
		return false, "empty constraint"
	}
	if len(raw) > 253 {
		return false, "constraint longer than 253 octets"
	}

	normalized := strings.TrimSuffix(raw, ".")
	if normalized == "" {
		return false, "root constraint (\".\") is not a usable DNS namespace"
	}
	if strings.Contains(normalized, "..") {
		return false, "contains an empty label"
	}

	labels := strings.Split(normalized, ".")
	for _, label := range labels {
		if label == "" {
			return false, "contains an empty label"
		}
		if len(label) > 63 {
			return false, "label longer than 63 octets"
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-', r == '_':
			default:
				return false, "contains an invalid character"
			}
		}
	}
	return true, ""
}

// icaIsSubDomainOf reports whether child is equal to parent or lies somewhere
// beneath parent in the DNS hierarchy. Comparison is label-boundary aware, so
// "notexample.com" is not considered a child of "example.com".
func icaIsSubDomainOf(child, parent string) bool {
	c := icaDomainLabels(child)
	p := icaDomainLabels(parent)
	if len(c) == 0 || len(p) == 0 || len(c) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if c[len(c)-1-i] != p[len(p)-1-i] {
			return false
		}
	}
	return true
}
