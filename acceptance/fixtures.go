package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// firingFixtures maps a checked-in unit-test fixture filename to the scenario
// id whose target certificate produces that finding.
var firingFixtures = map[string]string{
	"internalca_order_bad.pem":        "ext-order-a",
	"internalca_ca_no_certsign.pem":   "ca-no-certsign-a",
	"internalca_leaf_ku_unusable.pem": "leaf-ku-unusable-a",
	"internalca_ku_orphan.pem":        "ku-orphan-bit-a",
	"internalca_ca_nonminimal.pem":    "ca-ku-nonminimal-a",
	"internalca_nc_syntax_bad.pem":    "nc-dns-syntax-a",
	"internalca_nc_broad.pem":         "nc-dns-broad-a",
	"internalca_nc_redundant.pem":     "nc-dns-redundant-a",
}

// writeAllFixtures writes both the firing fixtures (taken from representative
// acceptance scenarios) and clean passing counterparts used by unit tests.
func writeAllFixtures(dir string, root *builtCert, scs []scenario) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	byID := map[string]scenario{}
	for _, sc := range scs {
		byID[sc.id] = sc
	}

	for name, id := range firingFixtures {
		sc, ok := byID[id]
		if !ok {
			return fmt.Errorf("fixture %s references unknown scenario %s", name, id)
		}
		ca, err := buildCert(sc.ca, root)
		if err != nil {
			return err
		}
		target := ca
		if sc.target == "leaf" {
			leaf, err := buildCert(sc.leaf, ca)
			if err != nil {
				return err
			}
			target = leaf
		}
		if err := os.WriteFile(filepath.Join(dir, name), target.pem, 0o644); err != nil {
			return err
		}
	}

	// Clean passing counterparts.
	goodCA, err := buildCert(goodCASpec("fixture-good-ca"), root)
	if err != nil {
		return err
	}
	goodLeaf, err := buildCert(goodLeafSpec("fixture-good-leaf", "app.internal.example"), goodCA)
	if err != nil {
		return err
	}
	passFixtures := map[string][]byte{
		"internalca_order_good.pem":      goodLeaf.pem,
		"internalca_leaf_ku_good.pem":    goodLeaf.pem,
		"internalca_ca_good.pem":         goodCA.pem,
		"internalca_nc_syntax_good.pem":  mustNCCA(root, []string{"permitted.internal"}, nil),
		"internalca_nc_nonredundant.pem": mustNCCA(root, []string{"foo.alpha.internal", "bar.beta.internal"}, nil),
	}
	for name, b := range passFixtures {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mustNCCA(root *builtCert, permitted, excluded []string) []byte {
	spec := goodCASpec("fixture-nc-ca")
	spec.ncPresent = true
	spec.ncCritical = true
	spec.ncPermitted = permitted
	spec.ncExcluded = excluded
	ca, err := buildCert(spec, root)
	if err != nil {
		panic(err)
	}
	return ca.pem
}
