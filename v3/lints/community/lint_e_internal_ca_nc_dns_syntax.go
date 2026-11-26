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
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type internalCANCDNSSyntax struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_internal_ca_nc_dns_syntax",
			Description:   "DNS name constraints must be syntactically valid domain names (no empty labels, whitespace or illegal characters). Malformed constraints are rejected by strict parsers/validators and make every chain through the CA invalid in the browser.",
			Citation:      "RFC 5280 Section 4.2.1.10 (name constraints dNSName form); RFC 1035 Section 2.3.1 label rules; internal CA profile name-constraint hygiene",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInternalCANCDNSSyntax,
	})
}

func NewInternalCANCDNSSyntax() lint.LintInterface {
	return &internalCANCDNSSyntax{}
}

func (l *internalCANCDNSSyntax) CheckApplies(c *x509.Certificate) bool {
	return c != nil && util.IsExtInCert(c, util.NameConstOID)
}

func (l *internalCANCDNSSyntax) Execute(c *x509.Certificate) *lint.LintResult {
	var problems []string

	check := func(kind string, constraints []x509.GeneralSubtreeString) {
		for _, subtree := range constraints {
			if ok, reason := icaValidDNSConstraint(subtree.Data); !ok {
				problems = append(problems, fmt.Sprintf("%s DNS constraint %q: %s", kind, subtree.Data, reason))
			}
		}
	}

	check("permitted", c.PermittedDNSNames)
	check("excluded", c.ExcludedDNSNames)

	if len(problems) > 0 {
		return &lint.LintResult{Status: lint.Error, Details: strings.Join(problems, "; ")}
	}
	return &lint.LintResult{Status: lint.Pass}
}
