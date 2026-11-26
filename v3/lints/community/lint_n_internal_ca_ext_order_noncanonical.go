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
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type internalCAExtOrderNoncanonical struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "n_internal_ca_ext_order_noncanonical",
			Description:   "Extensions should be encoded in the canonical internal CA profile order (basicConstraints, keyUsage, extKeyUsage, nameConstraints, subjectKeyIdentifier, authorityKeyIdentifier, subjectAltName, ...). Extension order is not required by RFC 5280 and does not cause browser rejection; this is an internal profile consistency check.",
			Citation:      "Internal CA Certificate Profile v1, section 'Extension ordering'; RFC 5280 Section 4.2 (extensions are identified by OID and order is not semantically significant)",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCAExtOrderNoncanonical,
	})
}

func NewInternalCAExtOrderNoncanonical() lint.LintInterface {
	return &internalCAExtOrderNoncanonical{}
}

func (l *internalCAExtOrderNoncanonical) CheckApplies(c *x509.Certificate) bool {
	return c != nil && len(c.Extensions) >= 2
}

func (l *internalCAExtOrderNoncanonical) Execute(c *x509.Certificate) *lint.LintResult {
	oids := make([]string, 0, len(c.Extensions))
	for _, ext := range c.Extensions {
		oids = append(oids, ext.Id.String())
	}
	ordered := icaRankSequence(oids)
	if len(ordered) < 2 {
		return &lint.LintResult{Status: lint.Pass}
	}

	// The canonical profile is a total order, so the ranks of the known
	// extensions must be non-decreasing in encoded order. Equal ranks only
	// occur for duplicate OIDs, which are another lint's responsibility.
	for i := 1; i < len(ordered); i++ {
		prev, cur := ordered[i-1], ordered[i]
		if cur.rank < prev.rank {
			return &lint.LintResult{
				Status:  lint.Notice,
				Details: fmt.Sprintf("extension %q should precede %q in the internal CA profile order", cur.name, prev.name),
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
