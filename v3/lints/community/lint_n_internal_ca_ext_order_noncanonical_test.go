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

func TestInternalCAExtOrderNoncanonical(t *testing.T) {
	cases := []struct {
		name string
		file string
		want lint.LintStatus
	}{
		{"out of profile order", "internalca/internalca_order_bad.pem", lint.Notice},
		{"canonical profile order", "internalca/internalca_order_good.pem", lint.Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := test.TestLint("n_internal_ca_ext_order_noncanonical", tc.file)
			if out.Status != tc.want {
				t.Errorf("%s: expected %s, got %s (%s)", tc.file, tc.want, out.Status, out.Details)
			}
		})
	}
}
