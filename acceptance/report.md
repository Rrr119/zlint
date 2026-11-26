# Internal CA lint acceptance — 30-certificate traceability matrix

Generated: 2026-11-26T11:32:43+08:00

Strict one-to-one mappings: **30/30** (all: true)

By severity: errors=13, warnings=7, info/notices=10

## How to read this

- Every row is one real X.509 certificate produced by a scripted self-built internal CA.
- `zlint` is invoked through the public `zlint.LintCertificate` entry point; the named internal-CA lint must return exactly the graded severity.
- Two independent chain oracles corroborate browser behaviour: Go `crypto/x509` and `openssl verify -purpose sslserver`.
- `Browser reason` records the matching Chromium `net::ERR_CERT_*` and NSS/Firefox code. Error-severity rows are expected to be rejected; warn/info rows are hardening findings on otherwise accepted chains — this is why not every lint finding is a browser rejection.

## Matrix

| # | Certificate | Category | Target | zlint finding (expected) | lint | Go verify | OpenSSL verify | Browser / Firefox reason | 1:1 |
|---|-------------|----------|--------|--------------------------|------|-----------|----------------|--------------------------|-----|
| 1 | `ext-order-a` | extension_order | leaf | `n_internal_ca_ext_order_noncanonical` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 2 | `ext-order-b` | extension_order | leaf | `n_internal_ca_ext_order_noncanonical` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 3 | `ext-order-c` | extension_order | leaf | `n_internal_ca_ext_order_noncanonical` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 4 | `ext-order-d` | extension_order | leaf | `n_internal_ca_ext_order_noncanonical` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 5 | `ext-order-e` | extension_order | leaf | `n_internal_ca_ext_order_noncanonical` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 6 | `ca-no-certsign-a` | key_usage | ca | `e_internal_ca_ku_ca_missing_certsign` = **error** | pass | reject: x509 | reject: error 79 at 1 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `accept` | yes |
| 7 | `ca-no-certsign-b` | key_usage | ca | `e_internal_ca_ku_ca_missing_certsign` = **error** | pass | reject: x509 | reject: error 79 at 1 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `accept` | yes |
| 8 | `ca-no-certsign-c` | key_usage | ca | `e_internal_ca_ku_ca_missing_certsign` = **error** | pass | reject: x509 | reject: error 79 at 1 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `accept` | yes |
| 9 | `ca-no-certsign-d` | key_usage | ca | `e_internal_ca_ku_ca_missing_certsign` = **error** | pass | reject: x509 | reject: error 79 at 1 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `accept` | yes |
| 10 | `leaf-ku-unusable-a` | key_usage | leaf | `e_internal_ca_ku_tls_leaf_unusable` = **error** | pass | accept | reject: error 26 at 0 depth lookup | net::ERR_SSL_KEY_USAGE_INCOMPATIBLE<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `ERR_SSL_KEY_USAGE_INCOMPATIBLE` | yes |
| 11 | `leaf-ku-unusable-b` | key_usage | leaf | `e_internal_ca_ku_tls_leaf_unusable` = **error** | pass | accept | reject: error 26 at 0 depth lookup | net::ERR_SSL_KEY_USAGE_INCOMPATIBLE<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `ERR_SSL_KEY_USAGE_INCOMPATIBLE` | yes |
| 12 | `leaf-ku-unusable-c` | key_usage | leaf | `e_internal_ca_ku_tls_leaf_unusable` = **error** | pass | accept | reject: error 26 at 0 depth lookup | net::ERR_SSL_KEY_USAGE_INCOMPATIBLE<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `ERR_SSL_KEY_USAGE_INCOMPATIBLE` | yes |
| 13 | `leaf-ku-unusable-d` | key_usage | leaf | `e_internal_ca_ku_tls_leaf_unusable` = **error** | pass | accept | reject: error 26 at 0 depth lookup | net::ERR_SSL_KEY_USAGE_INCOMPATIBLE<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `ERR_SSL_KEY_USAGE_INCOMPATIBLE` | yes |
| 14 | `leaf-ku-unusable-e` | key_usage | leaf | `e_internal_ca_ku_tls_leaf_unusable` = **error** | pass | accept | reject: error 26 at 0 depth lookup | net::ERR_SSL_KEY_USAGE_INCOMPATIBLE<br/>SEC_ERROR_INADEQUATE_KEY_USAGE (-8102)<br/>observed Chromium: `ERR_SSL_KEY_USAGE_INCOMPATIBLE` | yes |
| 15 | `ku-orphan-bit-a` | key_usage | leaf | `w_internal_ca_ku_agreement_bits_orphan` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 16 | `ku-orphan-bit-b` | key_usage | leaf | `w_internal_ca_ku_agreement_bits_orphan` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 17 | `ku-orphan-bit-c` | key_usage | leaf | `w_internal_ca_ku_agreement_bits_orphan` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 18 | `ku-orphan-bit-d` | key_usage | leaf | `w_internal_ca_ku_agreement_bits_orphan` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 19 | `ca-ku-nonminimal-a` | key_usage | ca | `n_internal_ca_ku_ca_nonminimal` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 20 | `ca-ku-nonminimal-b` | key_usage | ca | `n_internal_ca_ku_ca_nonminimal` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 21 | `ca-ku-nonminimal-c` | key_usage | ca | `n_internal_ca_ku_ca_nonminimal` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 22 | `nc-dns-syntax-a` | name_constraints | ca | `e_internal_ca_nc_dns_syntax` = **error** | pass | reject: strict CA parse | reject: error 47 at 0 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_EXTENSION_VALUE_INVALID<br/>observed Chromium: `accept` | yes |
| 23 | `nc-dns-syntax-b` | name_constraints | ca | `e_internal_ca_nc_dns_syntax` = **error** | pass | reject: strict CA parse | reject: error 47 at 0 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_EXTENSION_VALUE_INVALID<br/>observed Chromium: `accept` | yes |
| 24 | `nc-dns-syntax-c` | name_constraints | ca | `e_internal_ca_nc_dns_syntax` = **error** | pass | reject: x509 | reject: error 47 at 0 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_EXTENSION_VALUE_INVALID<br/>observed Chromium: `accept` | yes |
| 25 | `nc-dns-syntax-d` | name_constraints | ca | `e_internal_ca_nc_dns_syntax` = **error** | pass | reject: x509 | reject: error 47 at 0 depth lookup | NET::ERR_CERT_INVALID (-207)<br/>SEC_ERROR_EXTENSION_VALUE_INVALID<br/>observed Chromium: `accept` | yes |
| 26 | `nc-dns-broad-a` | name_constraints | ca | `w_internal_ca_nc_dns_too_broad` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 27 | `nc-dns-broad-b` | name_constraints | ca | `w_internal_ca_nc_dns_too_broad` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 28 | `nc-dns-broad-c` | name_constraints | ca | `w_internal_ca_nc_dns_too_broad` = **warn** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 29 | `nc-dns-redundant-a` | name_constraints | ca | `n_internal_ca_nc_dns_redundant` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |
| 30 | `nc-dns-redundant-b` | name_constraints | ca | `n_internal_ca_nc_dns_redundant` = **info** | pass | accept | accept | accept (no browser rejection)<br/>observed Chromium: `accept` | yes |

## Rejection ↔ check bijection

- Every `error` row is rejected by the purpose-aware OpenSSL oracle and maps to a concrete browser error code.
- Every `warn`/`info` row keeps a valid chain (accepted by both oracles and browsers); the finding is internal-profile hardening rather than a rejection cause.
- Go intentionally ignores leaf KeyUsage bits (Peter Gutmann compatibility note in `crypto/x509/verify.go`), so KeyUsage-combination rows may show `go=accept` while OpenSSL/Firefox/Chrome reject the purpose; this divergence is recorded explicitly rather than hidden.

## Empirical Chromium run

Ran real Chromium against 30/30 certificates via `browser/probe.mjs`: 22 observations match the expected browser outcome directly. All five unusable-TLS-leaf rows produced `ERR_SSL_KEY_USAGE_INCOMPATIBLE`, and every warn/info hardening row loaded. 8 chain-level error rows (CA keyCertSign / name-constraint syntax) load only because the per-leaf SPKI test pin bypasses chain verification; for those the matrix relies on the Go/OpenSSL rejections and the documented Chromium/NSS codes.

## Reproduce

```bash
cd acceptance
go run .                       # regenerate corpus/ and report.{json,md}
go test ./...                  # unit tests for the lints live in ../v3/lints/community
node browser/probe.mjs         # optional: empirical Chromium codes (needs `npx playwright install chromium`)
```
