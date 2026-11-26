// Command internalca-acceptance generates 30 real certificates from a
// scripted self-built internal CA, runs the internal_ca zlint checks over
// them and cross-checks every result against an independent chain verifier and
// the corresponding Chromium/Firefox rejection reason.
//
// Usage:
//
//	go run .                 # (re)generate corpus, verify, write report.md/json
//	go run . -no-gen         # verify the corpus already on disk
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	zlint "github.com/zmap/zlint/v3"
)

type rowResult struct {
	N                int    `json:"n"`
	ID               string `json:"id"`
	Title            string `json:"title"`
	Category         string `json:"category"`
	Target           string `json:"target"`
	Lint             string `json:"lint"`
	Severity         string `json:"severity"`
	LintStatus       string `json:"lint_status"`
	LintDetails      string `json:"lint_details,omitempty"`
	LintMatches      bool   `json:"lint_matches"`
	GoVerdict        string `json:"go_verdict"`
	OpenSSLVerdict   string `json:"openssl_verdict"`
	VerifierMatches  bool   `json:"verifier_matches"`
	BrowserReject    bool   `json:"browser_reject_expected"`
	ChromeReason     string `json:"chrome_reason"`
	FirefoxReason    string `json:"firefox_reason"`
	DNS              string `json:"dns"`
	ChromiumObserved string `json:"chromium_observed,omitempty"`
	ChromiumMatches  *bool  `json:"chromium_matches,omitempty"`
	OneToOne         bool   `json:"one_to_one"`
	TargetFile       string `json:"target_file"`
}

type report struct {
	GeneratedAt string         `json:"generated_at"`
	Total       int            `json:"total"`
	Passed      int            `json:"passed"`
	AllOneToOne bool           `json:"all_one_to_one"`
	BySeverity  map[string]int `json:"by_severity"`
	Rows        []rowResult    `json:"rows"`
}

func main() {
	outDir := flag.String("out", "corpus", "directory for generated certificates")
	reportPath := flag.String("report", "report.json", "path for the JSON report")
	markdownPath := flag.String("markdown", "report.md", "path for the Markdown matrix")
	browserResults := flag.String("browser-results", "browser/results.json", "optional Playwright Chromium observations")
	fixturesDir := flag.String("write-fixtures", "", "if set, also write unit-test PEM fixtures to this zlint testdata/internalca directory")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	root, err := buildCert(goodRootSpec(), nil)
	if err != nil {
		fatal(err)
	}
	mustWrite(filepath.Join(*outDir, "root.pem"), root.pem)

	var observed map[string]browserObservation
	if b, err := loadBrowserResults(*browserResults); err == nil {
		observed = b
		fmt.Printf("loaded %d Chromium observations from %s\n", len(b), *browserResults)
	}

	scs := scenarios()
	if len(scs) != 30 {
		fatal(fmt.Errorf("expected exactly 30 acceptance scenarios, got %d", len(scs)))
	}

	rep := report{GeneratedAt: time.Now().Format(time.RFC3339), Total: len(scs), BySeverity: map[string]int{}}
	workDir, err := os.MkdirTemp("", "ica-verify")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(workDir)
	mustWrite(filepath.Join(workDir, "root.pem"), root.pem)

	for _, sc := range scs {
		ca, err := buildCert(sc.ca, root)
		if err != nil {
			fatal(fmt.Errorf("%s CA: %w", sc.id, err))
		}
		leaf, err := buildCert(sc.leaf, ca)
		if err != nil {
			fatal(fmt.Errorf("%s leaf: %w", sc.id, err))
		}

		targetPEM := ca.pem
		if sc.target == "leaf" {
			targetPEM = leaf.pem
		}
		// Exactly one NN-id.target.pem per scenario: these are the 30
		// certificates that zlint is evaluated against. The .ca/.leaf files
		// are the matching chain material used by the verifier/browser probe.
		targetFile := fmt.Sprintf("%02d-%s.target.pem", sc.n, sc.id)
		mustWrite(filepath.Join(*outDir, targetFile), targetPEM)
		mustWrite(filepath.Join(*outDir, fmt.Sprintf("%02d-%s.ca.pem", sc.n, sc.id)), ca.pem)
		mustWrite(filepath.Join(*outDir, fmt.Sprintf("%02d-%s.leaf.pem", sc.n, sc.id)), leaf.pem)
		mustWrite(filepath.Join(*outDir, fmt.Sprintf("%02d-%s.leaf.key", sc.n, sc.id)), leafKeyPEM(leaf.key))

		// --- zlint through the public, existing lint entry point ----------
		zc, perr := zlintParse(targetPEM)
		if perr != nil {
			fatal(fmt.Errorf("%s: zcrypto parse failed: %w", sc.id, perr))
		}
		rs := zlint.LintCertificate(zc)
		lr := rs.Results[sc.lint]
		if lr == nil {
			fatal(fmt.Errorf("%s: lint %q not registered in ResultSet", sc.id, sc.lint))
		}
		status := lr.Status.String()
		lintMatches := status == sc.severity

		// --- Independent verifier oracle over the full leaf chain ---------
		goV := goVerify(root.pem, ca.pem, leaf.pem, sc.dns)
		mustWrite(filepath.Join(workDir, "ca.pem"), ca.pem)
		leafBase := fmt.Sprintf("leaf-%02d.pem", sc.n)
		mustWrite(filepath.Join(workDir, leafBase), leaf.pem)
		osslV := opensslVerify(workDir, leafBase)

		goReject := strings.HasPrefix(goV, "reject")
		osslReject := strings.HasPrefix(osslV, "reject")
		verifierMatches := goReject == sc.expectGoReject && osslReject == sc.expectOpenSSLReject

		row := rowResult{
			N: sc.n, ID: sc.id, Title: sc.title, Category: sc.category, Target: sc.target,
			Lint: sc.lint, Severity: sc.severity, LintStatus: status, LintDetails: lr.Details,
			LintMatches: lintMatches, GoVerdict: goV, OpenSSLVerdict: osslV,
			VerifierMatches: verifierMatches, BrowserReject: sc.browserReject,
			ChromeReason: sc.chrome, FirefoxReason: sc.firefox, DNS: sc.dns, TargetFile: targetFile,
		}

		if obs, ok := observed[sc.id]; ok {
			if obs.NavigationOK {
				row.ChromiumObserved = "accept"
			} else {
				row.ChromiumObserved = obs.ChromiumError
			}
			match := chromiumMatches(obs, sc)
			row.ChromiumMatches = &match
		}

		row.OneToOne = lintMatches && verifierMatches && sc.browserReject == sc.expectOpenSSLReject
		if row.OneToOne {
			rep.Passed++
		}
		rep.BySeverity[sc.severity]++
		rep.Rows = append(rep.Rows, row)

		flag := "OK "
		if !row.OneToOne {
			flag = "XX "
		}
		fmt.Printf("%s%02d %-26s lint=%-5s(%-4s) go=%-6v ossl=%-6v\n",
			flag, sc.n, sc.id, status, sc.severity, goReject, osslReject)
	}

	rep.AllOneToOne = rep.Passed == rep.Total
	writeJSON(*reportPath, rep)
	writeMarkdown(*markdownPath, rep)

	if *fixturesDir != "" {
		if err := writeAllFixtures(*fixturesDir, root, scs); err != nil {
			fatal(err)
		}
		fmt.Println("wrote unit-test fixtures to", *fixturesDir)
	}

	fmt.Printf("\n%d/%d scenarios have a strict one-to-one mapping -> %s\n", rep.Passed, rep.Total, *markdownPath)
	if !rep.AllOneToOne {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "acceptance:", err)
	os.Exit(1)
}

func mustWrite(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(err)
	}
}

func writeJSON(path string, rep report) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal(err)
	}
	mustWrite(path, b)
}

type browserObservation struct {
	ID            string `json:"id"`
	ChromiumError string `json:"chromiumError"`
	NavigationOK  bool   `json:"navigationOk"`
}

func loadBrowserResults(path string) (map[string]browserObservation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []browserObservation
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	m := map[string]browserObservation{}
	for _, o := range list {
		m[o.ID] = o
	}
	return m, nil
}

func chromiumMatches(o browserObservation, sc scenario) bool {
	if sc.browserReject {
		// Expect a Chromium net error code (cert- or SSL-layer), not load.
		return !o.NavigationOK && strings.Contains(o.ChromiumError, "ERR_")
	}
	return o.NavigationOK
}
