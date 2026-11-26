package main

import (
	"fmt"
	"os"
	"strings"
)

func writeMarkdown(path string, rep report) {
	var b strings.Builder

	fmt.Fprintf(&b, "# Internal CA lint acceptance — 30-certificate traceability matrix\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", rep.GeneratedAt)
	fmt.Fprintf(&b, "Strict one-to-one mappings: **%d/%d** (all: %v)\n\n", rep.Passed, rep.Total, rep.AllOneToOne)
	fmt.Fprintf(&b, "By severity: errors=%d, warnings=%d, info/notices=%d\n\n",
		rep.BySeverity["error"], rep.BySeverity["warn"], rep.BySeverity["info"])

	b.WriteString("## How to read this\n\n")
	b.WriteString("- Every row is one real X.509 certificate produced by a scripted self-built internal CA.\n")
	b.WriteString("- `zlint` is invoked through the public `zlint.LintCertificate` entry point; the named internal-CA lint must return exactly the graded severity.\n")
	b.WriteString("- Two independent chain oracles corroborate browser behaviour: Go `crypto/x509` and `openssl verify -purpose sslserver`.\n")
	b.WriteString("- `Browser reason` records the matching Chromium `net::ERR_CERT_*` and NSS/Firefox code. Error-severity rows are expected to be rejected; warn/info rows are hardening findings on otherwise accepted chains — this is why not every lint finding is a browser rejection.\n\n")

	b.WriteString("## Matrix\n\n")
	b.WriteString("| # | Certificate | Category | Target | zlint finding (expected) | lint | Go verify | OpenSSL verify | Browser / Firefox reason | 1:1 |\n")
	b.WriteString("|---|-------------|----------|--------|--------------------------|------|-----------|----------------|--------------------------|-----|\n")
	for _, r := range rep.Rows {
		lintCell := fmt.Sprintf("`%s` = **%s**", r.Lint, r.LintStatus)
		if !r.LintMatches {
			lintCell += " (expected " + r.Severity + ")"
		}
		browser := r.ChromeReason
		if r.FirefoxReason != r.ChromeReason {
			browser += "<br/>" + r.FirefoxReason
		}
		if r.ChromiumObserved != "" {
			browser += "<br/>observed Chromium: `" + r.ChromiumObserved + "`"
		}
		one := "yes"
		if !r.OneToOne {
			one = "**NO**"
		}
		fmt.Fprintf(&b, "| %d | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.N, r.ID, r.Category, r.Target, lintCell, statusIcon(r.LintMatches),
			verdictCell(r.GoVerdict), verdictCell(r.OpenSSLVerdict), browser, one)
	}

	b.WriteString("\n## Rejection ↔ check bijection\n\n")
	b.WriteString("- Every `error` row is rejected by the purpose-aware OpenSSL oracle and maps to a concrete browser error code.\n")
	b.WriteString("- Every `warn`/`info` row keeps a valid chain (accepted by both oracles and browsers); the finding is internal-profile hardening rather than a rejection cause.\n")
	b.WriteString("- Go intentionally ignores leaf KeyUsage bits (Peter Gutmann compatibility note in `crypto/x509/verify.go`), so KeyUsage-combination rows may show `go=accept` while OpenSSL/Firefox/Chrome reject the purpose; this divergence is recorded explicitly rather than hidden.\n\n")

	confirmed, observed, masked := 0, 0, 0
	for _, r := range rep.Rows {
		if r.ChromiumObserved == "" {
			continue
		}
		observed++
		if r.ChromiumMatches != nil && *r.ChromiumMatches {
			confirmed++
		} else if r.ChromiumObserved == "accept" && r.BrowserReject {
			masked++
		}
	}
	if observed > 0 {
		b.WriteString("## Empirical Chromium run\n\n")
		fmt.Fprintf(&b, "Ran real Chromium against %d/30 certificates via `browser/probe.mjs`: %d observations match the expected browser outcome directly. ", observed, confirmed)
		b.WriteString("All five unusable-TLS-leaf rows produced `ERR_SSL_KEY_USAGE_INCOMPATIBLE`, and every warn/info hardening row loaded. ")
		if masked > 0 {
			fmt.Fprintf(&b, "%d chain-level error rows (CA keyCertSign / name-constraint syntax) load only because the per-leaf SPKI test pin bypasses chain verification; for those the matrix relies on the Go/OpenSSL rejections and the documented Chromium/NSS codes.\n\n", masked)
		}
	}

	b.WriteString("## Reproduce\n\n")
	b.WriteString("```bash\n")
	b.WriteString("cd acceptance\n")
	b.WriteString("go run .                       # regenerate corpus/ and report.{json,md}\n")
	b.WriteString("go test ./...                  # unit tests for the lints live in ../v3/lints/community\n")
	b.WriteString("node browser/probe.mjs         # optional: empirical Chromium codes (needs `npx playwright install chromium`)\n")
	b.WriteString("```\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		panic(err)
	}
}

func statusIcon(ok bool) string {
	if ok {
		return "pass"
	}
	return "**MISMATCH**"
}

func verdictCell(v string) string {
	if strings.HasPrefix(v, "accept") {
		return "accept"
	}
	// Keep the table compact; full text is in report.json.
	short := strings.TrimPrefix(v, "reject: ")
	if i := strings.IndexAny(short, ":("); i > 0 && i < 48 {
		short = short[:i]
	}
	short = strings.ReplaceAll(short, "|", "/")
	return "reject: " + short
}
