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

type internalCAKUAgreementBitsOrphan struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_internal_ca_ku_agreement_bits_orphan",
			Description:   "The encipherOnly/decipherOnly keyUsage bits only have a defined meaning when keyAgreement is also asserted; asserting either without keyAgreement is an incoherent combination that can be misinterpreted by validators.",
			Citation:      "RFC 5280 Section 4.2.1.3 ('The meaning ... is only defined when the keyAgreement bit is also set'); internal CA profile keyUsage combination guidance",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCAKUAgreementBitsOrphan,
	})
}

func NewInternalCAKUAgreementBitsOrphan() lint.LintInterface {
	return &internalCAKUAgreementBitsOrphan{}
}

func (l *internalCAKUAgreementBitsOrphan) CheckApplies(c *x509.Certificate) bool {
	return c != nil && util.HasKeyUsageOID(c)
}

func (l *internalCAKUAgreementBitsOrphan) Execute(c *x509.Certificate) *lint.LintResult {
	if util.HasKeyUsage(c, x509.KeyUsageKeyAgreement) {
		return &lint.LintResult{Status: lint.Pass}
	}
	orphan := x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly
	if c.KeyUsage&orphan == 0 {
		return &lint.LintResult{Status: lint.Pass}
	}

	which := "encipherOnly"
	if c.KeyUsage&x509.KeyUsageDecipherOnly != 0 && c.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		which = "encipherOnly and decipherOnly"
	} else if c.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		which = "decipherOnly"
	}
	return &lint.LintResult{
		Status:  lint.Warn,
		Details: which + " asserted without keyAgreement; these bits are only meaningful in combination with keyAgreement",
	}
}
