# Vendored SAML 2.0 / XML-DSig / XML-Enc schemas

Normative XSDs used by the handler-package tests to validate Shyntr's SAML output
with tooling that shares no code with the signer (xmllint). Fetched from their
OASIS / W3C canonical locations on **2026-07-23**. Do not substitute copies from
other sources.

| File | Source URL | SHA-256 (as fetched) |
|---|---|---|
| `saml-schema-protocol-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd | `554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e` |
| `saml-schema-assertion-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd | `006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b` |
| `xmldsig-core-schema.xsd` | https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd | `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c` |
| `xenc-schema.xsd` | https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd | `5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e` |
| `xml.xsd` | https://www.w3.org/2001/xml.xsd | `61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c` |

The SHA-256 column records the bytes **as fetched**. The `schemaLocation`
rewrites below (needed for offline resolution) change some files, so their
current on-disk SHA-256 will differ from the value above for the three edited
files; the table is the provenance of the original download.

## `schemaLocation` rewrites (for offline `--nonet` resolution)

The OASIS/W3C schemas reference each other by absolute remote URL. Each remote
reference was rewritten to the local sibling filename so the import chain resolves
without network access. Only `<import>` `schemaLocation` values were changed;
nothing else was touched.

| File | Original `schemaLocation` | New value | Why |
|---|---|---|---|
| `saml-schema-assertion-2.0.xsd` | `http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd` | `xmldsig-core-schema.xsd` | resolve `ds:` import locally |
| `saml-schema-assertion-2.0.xsd` | `http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd` | `xenc-schema.xsd` | resolve `xenc:` import locally |
| `saml-schema-protocol-2.0.xsd` | `http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd` | `xmldsig-core-schema.xsd` | resolve `ds:` import locally |
| `xenc-schema.xsd` | `http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd` | `xmldsig-core-schema.xsd` | resolve `ds:` import locally |

Not edited:
- `saml-schema-protocol-2.0.xsd` already referenced `saml-schema-assertion-2.0.xsd` by relative path.
- `xmldsig-core-schema.xsd` has no `<import>`/`schemaLocation`.
- `xml.xsd` — its only `schemaLocation` occurrences are inside `<xs:documentation>`
  `<pre>` examples (escaped `&lt;import…`), not real imports; left untouched.
  No SAML/DSig/XEnc schema imports the `xml` namespace, so `xml.xsd` is not part
  of the active import chain for Response validation. It is vendored per the
  provenance set for completeness.

## Offline resolution proof

```
xmllint --nonet --noout --schema saml-schema-protocol-2.0.xsd <minimal-response.xml>
=> validates   (exit 0)
```
Confirms the protocol → assertion → {xmldsig, xenc} import chain resolves with no
network access.
