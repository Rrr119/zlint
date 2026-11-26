package community

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

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestInternalCAKUAgreementBitsOrphan(t *testing.T) {
	cases := []struct {
		file string
		want lint.LintStatus
	}{
		{"internalca/internalca_ku_orphan.pem", lint.Warn},
		{"internalca/internalca_leaf_ku_good.pem", lint.Pass},
	}
	for _, tc := range cases {
		out := test.TestLint("w_internal_ca_ku_agreement_bits_orphan", tc.file)
		if out.Status != tc.want {
			t.Errorf("%s: expected %s, got %s (%s)", tc.file, tc.want, out.Status, out.Details)
		}
	}
}
