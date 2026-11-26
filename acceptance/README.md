# Internal-CA practice lints — 30-certificate acceptance

This directory is the acceptance harness for the `internal_ca` family of
community lints added to zlint. It generates **30 real X.509 certificates**
from a scripted self-built internal CA, runs the new zlint checks against
them, and cross-references every result with an independent chain verifier and
the corresponding Chromium / Firefox rejection reason.

The lints themselves live in
[`../v3/lints/community`](../v3/lints/community) and use the ordinary zlint
certificate-lint interface and registry, so they work with the CLI, profiles,
filtering and JSON output exactly like every upstream lint.

## The checks

| Lint | Severity | What it checks | Browser relevance |
|------|----------|----------------|-------------------|
| `e_internal_ca_ku_ca_missing_certsign` | error | CA (`basicConstraints CA:TRUE`) with a `keyUsage` that omits `keyCertSign` | Chain cannot sign certificates; `ERR_CERT_INVALID` / `SEC_ERROR_INADEQUATE_KEY_USAGE` |
| `e_internal_ca_ku_tls_leaf_unusable` | error | TLS server-auth leaf whose KU has none of `digitalSignature`, `keyEncipherment`, `keyAgreement` | `ERR_SSL_KEY_USAGE_INCOMPATIBLE` (verified in real Chromium) / `SEC_ERROR_INADEQUATE_KEY_USAGE` |
| `e_internal_ca_nc_dns_syntax` | error | Malformed DNS name constraint (empty label, whitespace/illegal char, over-length/root form) | Strict parsers reject the CA; surfaces as `ERR_CERT_INVALID` or `ERR_CERT_NAME_CONSTRAINT_VIOLATION` |
| `w_internal_ca_ku_agreement_bits_orphan` | warn | `encipherOnly`/`decipherOnly` asserted without `keyAgreement` (bits only defined in that combination) | Interoperability ambiguity; usually still accepted |
| `w_internal_ca_nc_dns_too_broad` | warn | Permitted DNS constraint is a single-label/TLD-wide namespace (e.g. `test`, `internal`, `local`) | Over-broad scope / least-privilege failure; chain still valid |
| `n_internal_ca_ext_order_noncanonical` | info | Extensions not in the documented internal-profile order | Order is not a validation rule (RFC 5280 identifies extensions by OID); consistency only |
| `n_internal_ca_ku_ca_nonminimal` | info | Signing CA KU mixes in `keyEncipherment`/`dataEncipherment` | Least-privilege hardening; chain still valid |
| `n_internal_ca_nc_dns_redundant` | info | A permitted DNS constraint is already covered by a broader permitted constraint | Profile hygiene; chain still valid |

Severity follows zlint's naming contract: `e_*` returns `lint.Error`,
`w_*` returns `lint.Warn`, `n_*` returns `lint.Notice` ("info" in JSON).

## Interface compatibility

- Each check implements `lint.CertificateLintInterface` (`CheckApplies` /
  `Execute`) and registers in `init()` via `lint.RegisterCertificateLint`.
- Source is `lint.Community`; `EffectiveDate` is `util.ZeroDate`, so the
  checks apply to private/internal CAs regardless of CABF effective dates.
- Names pass the global `TestLintNames` prefix test and metadata passes
  `TestAllLintsHaveValidMeta`.
- Unit tests + PEM fixtures live in
  [`../v3/lints/community`](../v3/lints/community) and
  [`../v3/testdata/internalca`](../v3/testdata/internalca).

## Run it

```bash
# 1) unit tests for the eight lints
(cd ../v3 && go test ./lints/community/ -run InternalCA -v)

# 2) regenerate the 30 certs, verify and write report.md / report.json
go run .

# optional helper for the above
./run.sh

# 3) optional: empirical real-Chromium codes for all 30 certs
#    (needs a Chromium binary; `npx playwright install chromium` provides one.
#     if the host lacks libasound.so.2, put its dir on LD_LIBRARY_PATH)
node browser/probe.mjs
# then re-run `go run .` to merge browser/results.json into report.md
```

`go run .` exits non-zero unless all 30 scenarios satisfy the strict
one-to-one mapping (expected lint status **and** independent-verifier outcome).

## Corpus layout

`corpus/` is generated and intentionally contains throwaway private keys (the
keys are deterministic so SPKI pins stay reproducible). For each `NN-id`:

- `NN-id.target.pem` — **the** certificate zlint is scored on (30 total).
- `NN-id.ca.pem` / `NN-id.leaf.pem` / `NN-id.leaf.key` — chain material for
  `openssl verify` and the HTTPS browser probe.
- `root.pem` — the self-built trust anchor.

Distribution: extension order 5, CA KU 4, TLS-leaf KU 5, orphan KU bits 4,
non-minimal CA KU 3, NC syntax 4, NC too-broad 3, NC redundant 2 = 30.

## Browser-reason correspondence

The full per-certificate matrix is in [`report.md`](report.md) and the
machine-readable form in [`report.json`](report.json). Summary of the mapping:

| Defect archetype | Go `crypto/x509` | `openssl verify -purpose sslserver` | Chromium | Firefox / NSS |
|------------------|------------------|--------------------------------------|----------|---------------|
| CA without `keyCertSign` | reject: parent cannot sign | error 79 invalid CA / 32 no cert signing | `ERR_CERT_INVALID` | `SEC_ERROR_INADEQUATE_KEY_USAGE` |
| TLS leaf with no usable KU bit | accept* | error 26 unsuitable certificate purpose | `ERR_SSL_KEY_USAGE_INCOMPATIBLE` (observed) | `SEC_ERROR_INADEQUATE_KEY_USAGE` |
| Malformed DNS name constraint | reject: parse / not permitted | error 47 permitted subtree violation | `ERR_CERT_INVALID` or `ERR_CERT_NAME_CONSTRAINT_VIOLATION` | `SEC_ERROR_EXTENSION_VALUE_INVALID` / `SEC_ERROR_CERT_NOT_IN_NAME_SPACE` |
| A valid-but-hardening issue (order, orphan bits with an operable bit, broad/redundant NC, non-minimal CA) | accept | accept | accept (observed) | accept |

\* Go deliberately ignores leaf KeyUsage bits for compatibility (see the
Peter Gutmann comment in `crypto/x509/verify.go`), so the harness records the
Go result and the purpose-aware OpenSSL result separately instead of treating
`go=accept` as proof that a browser accepts.

A real Chromium 159 was executed against every certificate with
[`browser/probe.mjs`](browser/probe.mjs) and the observations are committed in
[`browser/results.json`](browser/results.json). All 17 hardening certificates
loaded and all 5 unusable-leaf certificates produced
`ERR_SSL_KEY_USAGE_INCOMPATIBLE`. The 8 chain-level error certificates
(CA `keyCertSign`, NC syntax) are masked by the per-leaf
`--ignore-certificate-errors-spki-list` test pin, which bypasses chain
verification; those rows are therefore evidenced by the Go/OpenSSL rejections
and the documented error codes rather than a pinned browser run.
