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

type internalCANCDNSTooBroad struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_internal_ca_nc_dns_too_broad",
			Description:   "A permitted DNS name constraint should scope the internal CA to a concrete namespace. Single-label constraints (e.g. .corp/.internal style roots) or constraints that are themselves a top-level domain permit issuance for an entire broad namespace and violate least-privilege scoping.",
			Citation:      "Internal CA Certificate Profile v1, 'Name constraints must be narrowly scoped'; RFC 5280 Section 4.2.1.10",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCANCDNSTooBroad,
	})
}

func NewInternalCANCDNSTooBroad() lint.LintInterface {
	return &internalCANCDNSTooBroad{}
}

func (l *internalCANCDNSTooBroad) CheckApplies(c *x509.Certificate) bool {
	return c != nil && len(c.PermittedDNSNames) > 0
}

func (l *internalCANCDNSTooBroad) Execute(c *x509.Certificate) *lint.LintResult {
	var broad []string
	for _, subtree := range c.PermittedDNSNames {
		d := icaNormalizeDomain(subtree.Data)
		labels := icaDomainLabels(d)
		if len(labels) == 0 {
			continue // malformed entries are reported by e_internal_ca_nc_dns_syntax
		}
		if len(labels) == 1 {
			broad = append(broad, subtree.Data)
		}
	}
	if len(broad) > 0 {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: fmt.Sprintf("permitted DNS name constraint(s) %v scope a top-level or single-label namespace; constrain a concrete domain instead", broad),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
