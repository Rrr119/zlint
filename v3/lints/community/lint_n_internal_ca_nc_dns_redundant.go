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

type internalCANCDNSRedundant struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "n_internal_ca_nc_dns_redundant",
			Description:   "A permitted DNS name constraint that is already covered by another, broader permitted constraint is redundant because RFC 5280 domain constraints permit zero or more labels to the left. Redundant constraints bloat the profile and can mask typos.",
			Citation:      "RFC 5280 Section 4.2.1.10 (a constraint such as host.example.com matches any name formed by adding labels to the left); internal CA profile name-constraint hygiene",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCANCDNSRedundant,
	})
}

func NewInternalCANCDNSRedundant() lint.LintInterface {
	return &internalCANCDNSRedundant{}
}

func (l *internalCANCDNSRedundant) CheckApplies(c *x509.Certificate) bool {
	return c != nil && len(c.PermittedDNSNames) >= 2
}

func (l *internalCANCDNSRedundant) Execute(c *x509.Certificate) *lint.LintResult {
	domains := make([]string, 0, len(c.PermittedDNSNames))
	for _, subtree := range c.PermittedDNSNames {
		d := icaNormalizeDomain(subtree.Data)
		if d != "" {
			domains = append(domains, d)
		}
	}

	var redundant []string
	for i, child := range domains {
		for j, parent := range domains {
			if i == j || child == parent {
				continue
			}
			// parent is broader than child when child is a proper sub-domain.
			if icaIsSubDomainOf(child, parent) && len(icaDomainLabels(child)) > len(icaDomainLabels(parent)) {
				redundant = append(redundant, fmt.Sprintf("%q is already permitted by %q", child, parent))
				break
			}
		}
	}

	if len(redundant) > 0 {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: fmt.Sprintf("redundant permitted DNS name constraint(s): %v", redundant),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
