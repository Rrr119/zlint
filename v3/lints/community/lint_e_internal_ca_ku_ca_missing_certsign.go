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

type internalCAKUCAMissingCertSign struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_internal_ca_ku_ca_missing_certsign",
			Description:   "A CA certificate that carries a keyUsage extension must assert keyCertSign; without it the certificate cannot sign other certificates and browsers reject every chain through it as an invalid CA / unsuitable certificate purpose.",
			Citation:      "RFC 5280 Section 4.2.1.3 (keyCertSign is required for CA certificate signing); internal CA profile 'CA keyUsage combination'",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCAKUCAMissingCertSign,
	})
}

func NewInternalCAKUCAMissingCertSign() lint.LintInterface {
	return &internalCAKUCAMissingCertSign{}
}

func (l *internalCAKUCAMissingCertSign) CheckApplies(c *x509.Certificate) bool {
	return c != nil && c.IsCA && util.HasKeyUsageOID(c)
}

func (l *internalCAKUCAMissingCertSign) Execute(c *x509.Certificate) *lint.LintResult {
	if util.HasKeyUsage(c, x509.KeyUsageCertSign) {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: "CA certificate keyUsage does not assert keyCertSign, so it cannot be used to verify issued certificates",
	}
}
