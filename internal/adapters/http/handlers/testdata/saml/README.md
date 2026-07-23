# Vendored SAML 2.0 / XML-DSig / XML-Enc schemas

Normative XSDs used by the handler-package tests (`saml_xmlverify_e2e_test.go`,
E1/E5) to validate Shyntr's SAML output with tooling that shares no code with the
signer (`xmllint`). Fetched from their OASIS / W3C canonical locations on
**2026-07-23**. Do not substitute copies from other sources.

## Provenance — every file is byte-identical to its canonical source

Each vendored file is stored **exactly as fetched** (no edits), so a third party
can verify provenance directly: fetch the URL, `shasum -a 256`, compare.

| File | Source URL | SHA-256 (as fetched = as committed) |
|---|---|---|
| `saml-schema-protocol-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd | `554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e` |
| `saml-schema-assertion-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd | `006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b` |
| `xmldsig-core-schema.xsd` | https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd | `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c` |
| `xenc-schema.xsd` | https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd | `5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e` |
| `xml.xsd` | https://www.w3.org/2001/xml.xsd | `61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c` |

Because the files are unedited, **there is a single hash per file** — as-fetched
equals as-committed. (OASIS schemas ship with CRLF, W3C with LF; `.gitattributes`
sets `*.xsd -text` so git never normalizes line endings and the committed bytes
keep matching these hashes.) An earlier iteration edited the `schemaLocation`
attributes for offline resolution, which changed some hashes; that approach is
**superseded** by the XML catalog below, which keeps every schema byte-exact.

## Offline resolution — `catalog.xml` (no schema edits)

The OASIS/W3C schemas reference each other by **remote** `xs:import`
`schemaLocation` URLs. Rather than edit them (which would break provenance),
`catalog.xml` — an OASIS XML catalog — maps each remote URL to its local sibling,
so `xmllint` resolves the whole import chain with **no network access**:

```
XML_CATALOG_FILES=<abs path>/catalog.xml \
  xmllint --nonet --catalogs --noout --schema saml-schema-protocol-2.0.xsd <response.xml>
```

Verified offline (`--nonet`) with no "failed to load external entity" warning.
The tests set `XML_CATALOG_FILES` and pass `--catalogs`; see `runXmllintSchema`.

Import chain resolved by the catalog: `protocol → {assertion (local), xmldsig}`,
`assertion → {xmldsig, xenc}`, `xenc → xmldsig`. `xml.xsd` is vendored for
completeness but is not referenced by this chain (no schema imports the `xml`
namespace).

## Test caching caveat

Go's test result cache does **not** invalidate when files in this directory
change (they are read by the external `xmllint`/`xmlsec1` processes; even
`//go:embed` was verified not to bust the cache). CI runs the verification tests
with `-count=1`. Locally, use `go test -count=1 ./internal/adapters/http/handlers`
after changing any schema. See the caveat comment atop `saml_xmlverify_e2e_test.go`.
