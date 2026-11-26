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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type internalCAKUTLSLeafUnusable struct{}

// icaTLSOperableUsages are the keyUsage bits that allow a certificate to take
// part in a TLS handshake: digitalSignature for (EC)DHE/ECDSA/RSA-PSS
// authentication, keyEncipherment for static RSA key transport and
// keyAgreement for static Diffie-Hellman/ECDH suites. encipherOnly and
// decipherOnly are modifiers rather than operations, so they do not qualify.
const icaTLSOperableUsages x509.KeyUsage = x509.KeyUsageDigitalSignature |
	x509.KeyUsageKeyEncipherment |
	x509.KeyUsageKeyAgreement

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_internal_ca_ku_tls_leaf_unusable",
			Description:   "A TLS server-auth end-entity certificate with a keyUsage extension must assert at least one bit that permits a TLS key operation (digitalSignature, keyEncipherment or keyAgreement); otherwise the keyUsage combination is unusable and browsers reject the certificate as an invalid/unsuitable certificate purpose.",
			Citation:      "RFC 5280 Section 4.2.1.3 and RFC 3279 Section 2.3; internal CA profile 'TLS subscriber keyUsage combination'",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCAKUTLSLeafUnusable,
	})
}

func NewInternalCAKUTLSLeafUnusable() lint.LintInterface {
	return &internalCAKUTLSLeafUnusable{}
}

func (l *internalCAKUTLSLeafUnusable) CheckApplies(c *x509.Certificate) bool {
	return c != nil && !c.IsCA && util.HasKeyUsageOID(c) && util.IsServerAuthCert(c)
}

func (l *internalCAKUTLSLeafUnusable) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage&icaTLSOperableUsages != 0 {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: "TLS server-auth certificate keyUsage contains none of digitalSignature/keyEncipherment/keyAgreement and cannot be used for a TLS key operation",
	}
}
