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

type internalCAKUCANonminimal struct{}

// A dedicated internal issuing CA is expected to only assert the certificate
// and CRL signing bits. The data-plane encipherment bits are unnecessary for a
// certificate-signing key and widen the damage if the key is misused.
const icaCAExtraneousUsages x509.KeyUsage = x509.KeyUsageKeyEncipherment |
	x509.KeyUsageDataEncipherment

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "n_internal_ca_ku_ca_nonminimal",
			Description:   "A signing CA certificate should keep keyUsage minimal (keyCertSign/cRLSign) and not assert keyEncipherment/dataEncipherment, which are end-entity data-plane operations. This is a least-privilege hardening recommendation and is not a browser rejection condition.",
			Citation:      "Internal CA Certificate Profile v1, 'CA keyUsage least privilege'; NIST SP 800-57 key usage guidance",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCAKUCANonminimal,
	})
}

func NewInternalCAKUCANonminimal() lint.LintInterface {
	return &internalCAKUCANonminimal{}
}

func (l *internalCAKUCANonminimal) CheckApplies(c *x509.Certificate) bool {
	return c != nil && c.IsCA && util.HasKeyUsageOID(c)
}

func (l *internalCAKUCANonminimal) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage&icaCAExtraneousUsages == 0 {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{
		Status:  lint.Notice,
		Details: "CA keyUsage includes keyEncipherment/dataEncipherment; a certificate-signing CA should limit itself to keyCertSign and cRLSign",
	}
}
