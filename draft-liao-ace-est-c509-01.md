---
v: 3

title: "EST for C509 Certificates"
docname: draft-liao-ace-est-c509-01
abbrev: EST-C509

cat: std
submissiontype: IETF

coding: utf-8

pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 4

venue:
  group: "Authentication and Authorization for Constrained Environments"
  type: "Working Group"
  mail: "ace@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ace/"
  github: "ace-wg/xxx"

author:
  - name: Lijun Liao
    org: NIO
    email: lijun.liao@nio.io

normative:
  RFC5280:
  RFC5652:
  RFC6402:
  RFC7030:
  RFC7250:
  RFC8615:
  RFC8949:
  RFC9277:
  RFC9810:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.liao-cose-c509-revocation:

informative:
  RFC2986:
  RFC9148:
  I-D.ietf-ace-coap-est-oscore:

--- abstract

This document defines Enrollment over Secure Transport (EST) protocol operations over HTTPS for use with C509 certificates. The operations specified in this document support CA certificate distribution, C509 certificate enrollment, C509 certificate re-enrollment, and server-side key generation using C509 certificates. This document also defines operations for Certificate Revocation List (CRL) distribution.

--- middle

# Introduction {#intro}

Enrollment over Secure Transport (EST) {{RFC7030}} defines HTTPS-based operations for X.509 {{RFC5280}} certificate enrollment and CA certificate distribution.  Payloads are DER-encoded and wrapped in CMS (Cryptographic Message Syntax, {{RFC5652}}) structures.  C509 {{I-D.ietf-cose-cbor-encoded-cert}} defines a compact, CBOR-encoded alternative to DER X.509 certificates.  C509 certificates are substantially smaller.

Although C509 was developed with constrained devices in mind, its benefits extend to unconstrained devices operating over low-bandwidth links and to large-scale deployments.  Smaller, CBOR-encoded certificates reduce bandwidth and storage requirements, accelerate TLS handshakes, and lower parsing and serialization overhead even on powerful endpoints; because C509 does not use ASN.1/DER, implementations can avoid complex ASN.1 parsing code, which reduces code size and complexity and lowers the attack surface for certificate parsing libraries.  In complex systems (for example, connected cars) that contain diverse device classes—microcontrollers, sensor chips, and SoCs—using a common certificate format wherever practical simplifies integration and provisioning.  Using C509 consistently across device classes simplifies provisioning, interoperability, and over-the-air updates, and can reduce overall operational costs and latency.

This document defines EST operations that carry C509 objects in place of DER X.509 objects, following the same HTTPS/TLS transport and URI path structure as {{RFC7030}}.  For environments where HTTPS/TLS is impractical, EST for C509 certificates over CoAP with OSCORE is defined in {{I-D.ietf-ace-coap-est-oscore}}.

A key property of this design is that EST clients do not require a CBOR parser or generator:

- For non-KEM-only key types, the C509 CSR is typically pre-provisioned as an opaque binary blob by the device manufacturer or a provisioning tool; the EST client sends it verbatim as the POST body of `simpleenroll` or `simplereenroll` without interpreting its contents.
[draft-liao-ace-est-c509-01.md](draft-liao-ace-est-c509-01.md)
- For KEM-only key types, the EST client needs to communicate with the key device to get the public key (`C509PublicKey`) and the certification request (`C509CertificationRequest`) after receiving the KEM challenge object (`KemChall`) from the EST server; in this case, the EST client considers the `C509PublicKey`, `KemChall`, and `C509CertificationRequest` opaque binary blobs.

- For all key types, the C509 certificate returned in the response is stored directly to persistent memory without parsing.  This property makes the EST client implementation extremely lightweight.

This document uses `C509CertificationRequest` as defined in {{I-D.ietf-cose-cbor-encoded-cert}} as the C509 Certificate Signing Request (C509 CSR) format.  An EST client uses a C509 CSR to request issuance of a C509 certificate from an EST server.

The operations defined in this document are:

~~~~~~~~~~~
+==========+============+=========+==============+=================+
| Opera-   | Category   | Client  | Request      | Response        |
| tion     |            | Authen- | Media Type   | Media Type      |
|          |            | tica-   |              |                 |
|          |            | tion    |              |                 |
+==========+============+=========+==============+=================+
| caps     | Capability | No      | (none)       | text/plain      |
|          | discovery  |         |              |                 |
+----------+------------+---------+--------------+-----------------+
| cacert   | CA cert.   | No      | (none)       | application/    |
|          | retrieval  |         |              | cose-c509-      |
|          |            |         |              | cert+cbor       |
+----------+------------+---------+--------------+-----------------+
| cacerts  | CA cert.   | No      | (none)       | application/    |
|          | chain      |         |              | cose-c509+cbor; |
|          | retrieval  |         |              | usage=chain     |
+----------+------------+---------+--------------+-----------------+
| crlinfo  | CRL        | No      | (none)       | application/    |
|          | metadata   |         |              | c509-crlinfo    |
|          | retrieval  |         |              | +cbor           |
+----------+------------+---------+--------------+-----------------+
| crl      | CRL        | No      | (none)       | application/    |
|          | retrieval  | No      |              | c509-crl+cbor   |
+----------+------------+---------+--------------+-----------------+
| csrattrs | CSR        | No      | (none)       | application/    |
|          | attributes |         |              | cose-c509-      |
|          | retrieval  |         |              | crtemplate+cbor |
+----------+------------+---------+--------------+-----------------+
| kemchall | KEM        | Yes     | application/ | application/    |
|          | challenge  |         | c509-pubkey  | cbor            |
|          | issuance   |         | +cbor        |                 |
+----------+------------+---------+--------------+-----------------+
| simple   | Cert.      | Yes     | application/ | application/    |
| enroll   | enrollment |         | cose-c509-   | cose-c509-      |
|          |            |         | pkcs10+cbor  | cert+cbor       |
+----------+------------+---------+--------------+-----------------+
| simple   | Cert. re-  | Yes     | application/ | application/    |
| reenroll | enrollment |         | cose-c509-   | cose-c509-      |
|          |            |         | pkcs10+cbor  | cert+cbor       |
+----------+------------+---------+--------------+-----------------+
| server   | Server-side| Yes     | application/ | application/    |
| keygen   | key        |         | cose-c509-   | cose-c509-      |
|          | generation |         | pkcs10+cbor  | pem+cbor        |
+----------+------------+---------+--------------+-----------------+
~~~~~~~~~~~
{: #tab-ops-overview title="Operations Defined in This Document"}

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

The following terms are used in this document:

EST client:
: The entity that contacts the EST server to obtain certificates or CA information, as defined in {{RFC7030, Section 1}}.

EST server:
: The entity that processes EST requests, typically acting as an RA between the EST client and the CA, as defined in {{RFC7030, Section 1}}.

CA:
: Certification Authority.  The entity that issues C509 certificates.

C509 CSR:
: C509 Certification Request.  A CBOR-encoded certification request used by an EST client to request issuance of a C509 certificate.

PoP:
: Proof of Possession.  Verification that the requester holds the private key corresponding to the public key in the C509 CSR.

# C509 Certification Request (C509 CSR) {#c509-csr}

A C509 CSR is a CBOR-encoded certification request used to request issuance of a C509 certificate.  It is the C509 analogue of the PKCS#10 CSR {{RFC2986}} used in standard EST operations.

This document uses `C509CertificationRequest` as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 4}}.  An EST client sends a C509 CSR to request certificate issuance or re-enrollment. The media type is `application/cose-c509-pkcs10+cbor`.

For server-side key generation requests ({{serverkeygen}}), the EST client does not possess the private key and does not know the public key that the EST server will generate.  In this case, the `subjectPublicKeyAlgorithm` in `TBSCertificationRequest` MUST be set to the integer code for `empty-publickey` (see {{empty-publickey}}) and `subjectPublicKey` MUST be an empty byte string (`h''`).  Because no private/public key is available, no PoP signature can be computed/verified: the `signatureAlgorithm` MUST be set to the `id-alg-unsigned` integer code and `signatureValue` MUST be a zero-length byte string.  EST servers MUST accept C509 CSRs using `empty-publickey` and `id-alg-unsigned` for `serverkeygen` requests and MUST NOT verify a PoP signature in this case.

## empty-publickey Algorithm {#empty-publickey}

This document defines a new C509 public key algorithm, `empty-publickey`, to be used exclusively in C509 CSRs for `serverkeygen` requests to indicate that no public key is available in the CSR.

The `empty-publickey` algorithm code (TBD1) MUST NOT appear in C509 certificates.  It is only valid in the `subjectPublicKeyAlgorithm` field of `TBSCertificationRequest` when the corresponding `subjectPublicKey` is an empty byte string (`h''`).  EST servers MUST reject any C509 CSR using `empty-publickey` in a `simpleenroll` or `simplereenroll` request.

## CRAttribute ChangeSubjectName {#change-subject-name}

The ChangeSubjectName for X.509 PKI is defined in {{RFC6402}}. The corresponding definition for C509 certification request is a CBOR-array consisting of a `subject` and a `subjectAlt`. At least one of `subject` and `subjectAlt` MUST NOT be `null`.

~~~~~~~~~~~cddl
ChangeSubjectName = [
  subject     C509Name / null,
  subjectAlt  SubjectAltName / null
]
~~~~~~~~~~~
{: sourcecode-name="c509est.cddl"}

This CRAttribute MAY be included in a `simplereenroll` request to change the `Subject` field and/or the `SubjectAltName` extension in the newly generated certificate.

## Proof of Possession

`simpleenroll` and `simplereenroll` MUST verify the PoP signature in the C509 CSR before issuing a certificate.  The `serverkeygen` operation does not require PoP verification because the EST server generates the key pair itself.

### C509PublicKey {#c509pubkey}

A `C509PublicKey` contains a subject public key in the C509 encoding.  It uses the same field types as `TbsCertificate` in {{I-D.ietf-cose-cbor-encoded-cert}} and is defined as:

~~~~~~~~~~~
C509PublicKey = [
  subjectPublicKeyAlgorithm : AlgorithmIdentifier,
  subjectPublicKey          : Defined
]
~~~~~~~~~~~
{: sourcecode-name="c509est.cddl"}

The `subjectPublicKeyAlgorithm` field uses the full `AlgorithmIdentifier` encoding as defined in {{I-D.ietf-cose-cbor-encoded-cert}}, without limitation.
The `subjectPublicKey` field uses the same encoding as in C509 certificates: for most algorithms it is a CBOR byte string, but for RSA public keys it is encoded as an array of two unwrapped CBOR unsigned bignums `[~biguint, ~biguint]` when the exponent is not 65537, as specified in {{I-D.ietf-cose-cbor-encoded-cert}}.

The media type of `C509PublicKey` is `application/c509-pubkey+cbor` (see {{iana-c509-pubkey}}); the corresponding CoAP Content-Format is defined in {{content-format}}.  The "magic number" is TBD2, using the reserved CBOR tag 55799 and Content-Format TBD3, as described in {{RFC9277, Section 2.2}}.

### Proof of Possession for KEM Private Keys {#pop-kem}

Some public-key algorithms are KEM-only (key-encapsulation mechanisms) and do not provide a signature operation suitable for the traditional PoP signature carried in a `C509CertificationRequest`.  For CSRs whose `subjectPublicKeyAlgorithm` is a KEM algorithm, an EST server MUST obtain explicit proof that the requester holds the corresponding KEM private key.  This document specifies an interactive KEM challenge–response PoP mechanism.

The recommended KEM PoP flow is:

- Challenge issuance: Upon receipt of a KEM public key (`C509PublicKey`) in the `kemchall` operation, an EST server returns a CBOR-encoded KEM challenge object (`KemChall`) with media type `application/cbor`.

~~~~~~~~~~~cddl
KemChall = [
  keyId         : bstr,
  encapAlg      : int,
  encapsulation : bstr
]
~~~~~~~~~~~
{: sourcecode-name="c509est.cddl"}

In particular:

- `keyId` is the SHA-256 fingerprint of the CBOR-encoded `C509PublicKey`,

- `encapAlg` is the encapsulation algorithm (TBD: define a new registry or reuse a COSE algorithm), and

- `encapsulation` is the KEM ciphertext produced by encapsulating a freshly generated one-time secret key `S` to the client's KEM public key.

The server MUST retain the challenge state (at least `keyId`, `S`, and the lifetime) for the duration of the challenge.

- Client decapsulation and response: The client decapsulates `encapsulation` to recover the one-time secret key `S`.  The client computes a MAC value over the CBOR-encoded `TBSCertificationRequest` with the key `S`.  The client then submits a follow-up operation as usual.

- Server verification: The server computes the `keyId`, retrieves the challenge state for that `keyId`, and verifies that the state is still within its validity period.  The server then derives `K` from `S` and verifies the received `mac` against the saved `TBSCertificationRequest`.  The server proceeds with certificate issuance as for signature-based PoP.  If verification fails or the challenge has expired, the server MUST reject the request.

Implementations SHOULD use HMAC-SHA256 (with integer value TBD4) by default, unless constrained by the KEM's security requirements.  Servers MUST enforce challenge timeouts and retry limits to mitigate replay and denial-of-service risks.

IANA is requested to register MAC algorithms to be used in `C509CertificationRequest` ({{iana-sigalg}}).

# EST URL Structure and Path Components {#est-url-structure}

The operations in this document follow the same URI path structure defined in {{RFC7030, Section 3.2.2}}.  Retrieval operations (`caps`, `cacert`, `cacerts`, `crlinfo`, `crl`) use HTTP GET:

~~~
Method: GET
Request target: /.well-known/cest/<operation>
Request target: /.well-known/cest/<label>/<operation>
~~~

Enrollment operations (`kemchall`, `simpleenroll`, `simplereenroll`, `serverkeygen`) use HTTP POST:

~~~
Method: POST
Request target: /.well-known/cest/<operation>
Request target: /.well-known/cest/<label>/<operation>
~~~

An EST server MUST return HTTP 405 (Method Not Allowed) if a client uses POST for a retrieval operation or GET for an enrollment operation.

The optional `<label>` path segment follows {{RFC7030, Section 3.2.2}}: an EST server MAY use an additional path segment before the operation name to distinguish services for multiple CAs or certificate profiles.

## CBOR Transfer {#cbor-transfer}

All POST request bodies in this document are CBOR-encoded.  CBOR-based response bodies are base64-encoded for transport.  The CBOR encoding MUST be deterministic as specified in {{RFC8949, Sections 4.2.1 and 4.2.2}}.  Servers MUST NOT include a `Content-Transfer-Encoding` header for CBOR payloads.

The media types used in this document are:

| Media Type | Structure | Defined in |
|:---|:---|:---|
| application/cose-c509-cert+cbor        | C509Certificate (single certificate) | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509+cbor;usage=chain | COSE_C509 | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509-pkcs10+cbor      | C509CertificationRequest | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/c509-pubkey+cbor           | C509PublicKey | this document |
| application/cbor                       | KemChall | this document |
| application/cose-c509-crtemplate+cbor  | C509CertificationRequestTemplate | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509-pem+cbor         | C509PEM (key + cert) | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/c509-crl+cbor              | C509CRL | {{I-D.liao-cose-c509-revocation}} |
| application/c509-crlinfo+cbor          | C509CRLInfo | {{I-D.liao-cose-c509-revocation}} |
{: #tab-media-types title="Media Types Used in This Document"}

The `caps` operation returns `text/plain` with a list of capability keywords.

# EST Server Capability Discovery {#caps-section}

## caps {#caps}

The `caps` operation allows an EST client to discover which C509-specific operations the EST server supports before invoking them.  EST clients and EST servers MUST support `caps`.

### Request {#caps-request}

The EST client sends a GET request for the server's C509 capability list.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/caps
~~~

### Response {#caps-response}

On success, the EST server returns a 200 response with:

- Media type: `text/plain`
- Body: A plain-text list of capability keywords, one keyword per line.  The EST server MUST terminate each line with `<CR><LF>`.  The EST client MUST be able to parse lines terminated by `<CR><LF>`, `<CR>`, or `<LF>`.  Keywords are unquoted and case-insensitive.

The following keywords are defined.  An EST server MUST include a keyword in the `caps` response if and only if it supports the corresponding operation.

| Keyword          | Description |
|:---|:---|
| `cacert`         | EST server supports `cacert` ({{cacert}}) |
| `cacerts`        | EST server supports `cacerts` ({{cacerts}}) |
| `crlinfo`        | EST server supports `crlinfo` ({{crlinfo}}) |
| `crl`            | EST server supports `crl` ({{crl}}) |
| `csrattrs`       | EST server supports `csrattrs` ({{csrattrs}}) |
| `kemchall`       | EST server supports `kemchall` ({{kemchall}}) |
| `simpleenroll`   | EST server supports `simpleenroll` ({{simpleenroll}}) |
| `simplereenroll` | EST server supports `simplereenroll` ({{simplereenroll}}) |
| `serverkeygen`   | EST server supports `serverkeygen` ({{serverkeygen}}) |
{: #tab-caps-keywords title="caps Keywords Defined in This Document"}

An EST client that receives an HTTP error response to a `caps` request MUST NOT attempt the operations defined in this document.

Example response:

~~~
cacert
cacerts
crlinfo
crl
csrattrs
kemchall
simpleenroll
simplereenroll
serverkeygen
~~~

## csrattrs {#csrattrs}

The `csrattrs` operation returns a `C509CertificationRequestTemplate` that an EST client MAY use to construct a C509 CSR.

### Request {#csrattrs-request}

The EST client sends a GET request for the CSR template.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/csrattrs
~~~

### Response {#csrattrs-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509-crtemplate+cbor`
- Body: A base64-encoded `C509CertificationRequestTemplate` as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

An HTTP response code of 204 or 404 indicates that CSR attributes are not available.

# Distribution of CA Certificates {#ca-certificates}

## cacert {#cacert}

The `cacert` operation returns the issuing CA certificate for the requested EST service as a single base64-encoded CBOR `C509Certificate`.

### Request {#cacert-request}

The EST client sends a GET request for the CA certificate.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/cacert
~~~

### Response {#cacert-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509-cert+cbor`
- Body: A base64-encoded `C509Certificate` for the issuing CA, as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

The response body contains exactly one C509 certificate.

Successful `cacert` responses SHOULD include HTTP caching metadata.  EST servers SHOULD include `ETag`, `Last-Modified`, `Cache-Control`, and `Expires` headers when the certificate lifetime provides a meaningful freshness bound.

## cacerts {#cacerts}

The `cacerts` operation returns the CA certificate chain for the requested EST service as a CBOR sequence of C509 certificates.

### Request {#cacerts-request}

The EST client sends a GET request for the CA certificate chain.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/cacerts
~~~

### Response {#cacerts-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509+cbor;usage=chain`
- Body: A base64-encoded `COSE_C509` representing an ordered certificate chain.  The first element is the issuing CA certificate; subsequent elements are intermediate and root CA certificates in chain order. If a Root CA key update applies, the EST server SHOULD include the three "Root CA Key Update" certificates OldWithOld, OldWithNew, and NewWithOld in the response chain.  These are defined in {{RFC9810, Section 4.4}}.

Successful `cacerts` responses SHOULD include HTTP caching metadata.

# Distribution of C509 CRLs {#crl-operations}

The `crlinfo` and `crl` operations provide C509 CRL access.  The C509 CRL format is defined in {{I-D.liao-cose-c509-revocation}}.

## crlinfo {#crlinfo}

The `crlinfo` operation returns metadata about the current C509 CRL for the target CA as a `C509CRLInfo` object without the full revocation list.  This enables an EST client to check whether its locally cached CRL is still current before requesting the full `crl`.  `C509CRLInfo` is defined in {{I-D.liao-cose-c509-revocation}}.

### Request {#crlinfo-request}

The EST client sends a GET request for CRL metadata.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/crlinfo
Request target: /.well-known/cest/<label>/crlinfo
                [?crlnumber=<n>][&crldp=<dp>]
~~~

The optional `crlnumber` query parameter carries the decimal representation of the CRL number the client is interested in.  When present, the EST server MUST return the `C509CRLInfo` for the CRL with that exact `crlNumber`.  If no CRL with the requested `crlnumber` is available, the EST server MUST return HTTP status 404 (Not Found).  When `crlnumber` is absent, the server returns the `C509CRLInfo` for the most recent CRL.

The optional `crldp` query parameter carries the CRL Distribution Point identifier.  When present, the EST server MUST return the `C509CRLInfo` for the CRL associated with that distribution point.  When both `crlnumber` and `crldp` are present, the server MUST return the `C509CRLInfo` matching both criteria.

### Response {#crlinfo-response}

On success, the EST server returns a 200 response with:

- Media type: `application/c509-crlinfo+cbor`
- Body: A base64-encoded `C509CRLInfo` as defined in {{I-D.liao-cose-c509-revocation}}.

`C509CRLInfo` carries all CRL fields from `C509CRLInfoData` — including `crlType`, `signatureAlgorithm`, `authoritySubject`, `authorityKeyIdentifier`, `crlNumber`, `thisUpdate`, `nextUpdate`, `baseCrlNumber`, and `crlExtensions` — without the `revokedCertsList`.  An EST client can use these fields to compare `crlNumber`, `nextUpdate`, or compute a freshness check against its local cache before deciding whether to download the full `C509CRL` via `crl`.

If no matching CRL is available, the EST server MUST return HTTP status 404 (Not Found).

## crl {#crl}

The `crl` operation returns the C509 CRL for the target CA.

### Request {#crl-request}

The EST client sends a GET request for the C509 CRL.  No request body is sent.  The EST server SHOULD NOT require client authentication for this operation.

~~~
Method: GET
Request target: /.well-known/cest/<label>/crl
Request target: /.well-known/cest/<label>/crl
                [?crlnumber=<n>][&crldp=<dp>]
~~~

The optional `crlnumber` query parameter carries the decimal representation of the CRL number.  When present, the EST server MUST return the full `C509CRL` with that exact `crlNumber`.  When `crlnumber` is absent, the server returns the most recent CRL.

The optional `crldp` query parameter carries the CRL Distribution Point identifier.  When present, the EST server MUST return the full `C509CRL` for the CRL associated with that distribution point.  When both `crlnumber` and `crldp` are present, the server MUST return the `C509CRL` matching both criteria.

If no matching CRL is available, the EST server MUST return HTTP status 404 (Not Found).

### Response {#crl-response}

On success, the EST server returns a 200 response with:

- Media type: `application/c509-crl+cbor`
- Body: A base64-encoded `C509CRL` as defined in {{I-D.liao-cose-c509-revocation}}.

Successful `crl` responses SHOULD include HTTP caching metadata.  When present, `Last-Modified` SHOULD reflect the CRL `thisUpdate` value, and when `nextUpdate` is present, `Expires` SHOULD reflect `thisUpdate + nextUpdate`.

If no matching CRL is available, the EST server MUST return HTTP status 404 (Not Found).

# Certificate Enrollment Operations {#enrollment-ops}

## Client Authentication {#enrollment-auth}

The enrollment operations defined in this section (`kemchall`, simpleenroll`, `simplereenroll`, and `serverkeygen`) require client authentication.  The client authentication requirements are unchanged from {{RFC7030}}.  EST clients and EST servers MUST follow {{RFC7030, Section 3.2.3}} and {{RFC7030, Section 3.3.2}} for client authentication, respectively.

## kemchall {#kemchall}

The `kemchall` operation requests a KEM-based Proof-of-Possession challenge for a submitted C509 public key whose `subjectPublicKeyAlgorithm` is a KEM algorithm.

### Request {#kemchall-request}

An authenticated EST client sends a POST request containing a `C509PublicKey` ({{c509pubkey}}) to request a KEM challenge.

~~~
Method: POST
Request target: /.well-known/cest/<label>/kemchall
Media type: application/c509-pubkey+cbor

<Base64-encoded C509PublicKey>
~~~

If the request does not contain a KEM public key, the EST server MUST return HTTP 400 (Bad Request).  If the server supports KEM PoP for the submitted algorithm, it issues a challenge; otherwise, it MUST return HTTP 501 (Not Implemented).

### Response {#kemchall-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cbor`
- Body: A base64-encoded `KemChall` ({{pop-kem}}).

A client that receives a `KemChall` uses the recovered one-time secret key to produce the PoP MAC and then proceeds with a normal enrollment request (`simpleenroll` or `simplereenroll`) including the computed MAC in the request (see {{pop-kem}} for the PoP flow). The EST server verifies the MAC using the stored challenge state and issues the certificate on success.


## simpleenroll {#simpleenroll}

The `simpleenroll` operation requests issuance of a new C509 certificate from the EST server.

### Request {#simpleenroll-request}

An authenticated EST client sends a POST request containing a C509 CSR ({{c509-csr}}).

~~~
Method: POST
Request target: /.well-known/cest/<label>/simpleenroll
Media type: application/cose-c509-pkcs10+cbor

<Base64-encoded C509CertificationRequest>
~~~

The `C509CertificationRequest` MUST include a valid PoP signature.  The EST server MUST verify the PoP signature against the public key in the C509 CSR before issuing a certificate, as required by {{RFC7030, Section 3.4}}.

### Response {#simpleenroll-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509-cert+cbor`
- Body: A base64-encoded `C509Certificate` issued for the subject in the C509 CSR, as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

## simplereenroll {#simplereenroll}

The `simplereenroll` operation renews or rekeys an existing C509 certificate.

### Request {#simplereenroll-request}

An authenticated EST client sends a POST request containing a C509 CSR for re-enrollment.  The request Subject field and SubjectAltName extension MUST be identical to the corresponding fields in the certificate being renewed or rekeyed.

The `ChangeSubjectName` attribute defined in {{change-subject-name}} MAY be included in the CSR to request that these fields be changed in the new certificate.

~~~
Method: POST
Request target: /.well-known/cest/<label>/simplereenroll
Media type: application/cose-c509-pkcs10+cbor

<Base64-encoded C509CertificationRequest>
~~~

Re-enrollment processing follows {{RFC7030, Section 4.2.2}}.  The EST server MUST verify the PoP signature in the C509 CSR.

### Response {#simplereenroll-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509-cert+cbor`
- Body: A base64-encoded renewed `C509Certificate`, as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

## serverkeygen {#serverkeygen}

The `serverkeygen` operation requests server-side key generation and returns the generated private key and the issued C509 certificate.

As discussed in {{RFC9148, Section 9}}, transporting private keys generated by the EST server is inherently risky. The use of server-generated private keys increases the risk of digital identity theft. Therefore, implementations SHOULD NOT use EST functions that rely on server-generated private keys.

### Request {#serverkeygen-request}

An authenticated EST client sends a POST request containing a C509 CSR.  The `subjectPublicKeyAlgorithm` in the C509 CSR SHOULD be set to `empty-publickey` ({{empty-publickey}}) and `subjectPublicKey` SHOULD be an empty byte string (`h''`), because the key pair is generated by the EST server.  The `signatureAlgorithm` SHOULD be the `id-alg-unsigned` integer code and `signatureValue` SHOULD be a zero-length byte string.  EST servers MUST accept C509 CSRs that use `empty-publickey` and `id-alg-unsigned` for `serverkeygen` and MUST NOT verify a PoP signature in this case.

~~~
Method: POST
Request target: /.well-known/cest/<label>/serverkeygen
Media type: application/cose-c509-pkcs10+cbor

<Base64-encoded C509CertificationRequest>
~~~

### Response {#serverkeygen-response}

On success, the EST server returns a 200 response with:

- Media type: `application/cose-c509-pem+cbor`
- Body: A base64-encoded `C509PEM`.

The `C509CertData` field in the `C509PEM` MUST contain only the issued C509 certificate for the generated key pair.

The EST server SHOULD delete the private key from its storage as soon as the response has been transmitted successfully, unless the deployment policy requires retention for key escrow or disaster recovery (see {{security}}).  The private key is protected only by the TLS channel; no additional encryption is applied.

# Security Considerations {#security}

The security requirements of {{RFC7030}} apply in full to all operations defined in this document.

## Transport Security

All operations defined in this document MUST be carried out over HTTPS (HTTP over TLS) as required by {{RFC7030, Section 3}}.  Implementations MUST NOT fall back to plain HTTP.

EST clients and servers SHOULD use C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}} for TLS authentication when both peers support C509.  This enables end-to-end C509 usage, including the TLS handshake itself, and reduces size and parsing overhead consistently.  EST servers MUST continue to accept X.509 certificates {{RFC5280}} for TLS client authentication for interoperability with clients that do not yet support C509.

### TLS Certificate Type Negotiation

When C509 certificates are used for TLS authentication, the client and server negotiate the certificate type using the `server_certificate_type` and `client_certificate_type` TLS extensions as defined in {{RFC7250}}.

### Client Authentication

The `caps`, `cacert`, `cacerts`, `crlinfo`, and `crl` operations SHOULD NOT require client authentication, consistent with {{RFC7030, Section 4.1.2}}.  The `kemchall`, `simpleenroll`, `simplereenroll`, and `serverkeygen` operations MUST require client authentication.

## Server Key Generation

The `serverkeygen` operation delivers a generated private key to the EST client over TLS.  EST servers SHOULD delete the private key after successful transmission.  EST clients MUST store the key material securely immediately upon receipt.

As discussed in {{RFC9148, Section 9}}, transporting private keys generated by the EST server is inherently risky. The use of server-generated private keys increases the risk of digital identity theft. Therefore, implementations SHOULD NOT use EST functions that rely on server-generated private keys.

## C509 Certificate Validation

EST clients MUST validate received C509 certificates against an independently configured trust anchor according to {{I-D.ietf-cose-cbor-encoded-cert}}.  The trust model for C509 certificates differs from classical X.509 certificate chain validation when C509 is used in the HyPKI trust architecture; in that case, validation uses the cosigner-signed Merkle tree or signed allowlist rather than a certificate chain.

# IANA Considerations {#iana}

## Well-Known URI Registry {#iana-well-known}

IANA is requested to register the following entry in the "Well-Known URI" registry established by {{RFC8615}}:

| URI Suffix | Change Controller | Reference | Status | Related Information |
|:---|:---|:---|:---|:---|
| `cest` | IETF | This document | permanent | C509 EST operations as defined in this document |
{: #tab-iana-well-known title="Well-Known URI Registration for cest"}

## C509 Public Key Algorithms Registry {#iana-pubkey}

IANA is requested to register the following entry in the "C509 Public Key Algorithms" registry under the registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}:

| Field | Value |
|:---|:---|
| Value | TBD1 |
| Name | empty-publickey |
| Identifiers | N/A |
| OID | N/A |
| Parameters | N/A |
| DER | N/A |
| Comments | Exclusively for use in `subjectPublicKeyAlgorithm` of a `TBSCertificationRequest` for server-side key generation (`serverkeygen`).  MUST NOT appear in C509 certificates. |
| Reference | This document |
{: #tab-iana-pubkey title="empty-publickey Registration"}

## C509 Signature Algorithms Registry {#iana-sigalg}

IANA is requested to register the following entry in the "C509 Signature Algorithms" registry under the registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}:

| Field | Value |
|:---|:---|
| Value | TBD4 |
| Name | hmacWithSHA256 |
| Identifiers | id-hmacWithSHA256 |
| OID | 1.2.840.113549.2.9 |
| Parameters | N/A |
| OID | 06 08 2A 86 48 86 F7 0D 02 09 |
| Comments | HMAC over SHA256 |
| Reference | This document |
{: #tab-iana-sigalg title="HMAC-SHA256 Registration"}

## C509 CR Attributes Registry {#iana-cratttype}

IANA is requested to register the following entry in the "C509 CR Attributes" registry under the registry group "CBOR Encoded X.509 (C509)" defined in {{I-D.ietf-cose-cbor-encoded-cert}}:

~~~
+-------+-----------------------------------------------------------+
| Value | CR Attribute                                              |
+=======+===========================================================+
|  TBD5 | Name:            CMC Change Subject Name                  |
|       | Identifiers:     id-cmc-changeSubjectName                 |
|       | OID:             1.3.6.1.5.5.7.7.36                       |
|       | DER:             06 08 2B 06 01 05 05 07 07 24            |
|       | Comments:        RFC 6402                                 |
|       | attributeValue:  ChangeSubjectName                        |
+-------+-----------------------------------------------------------+
~~~

### Media Type application/c509-pubkey+cbor {#iana-c509-pubkey}

When the `application/c509-pubkey+cbor` media type is used, the payload is a `C509PublicKey` structure.

Type name: application

Subtype name: c509-pubkey+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

Applications that use this media type: Applications that employ C509 public keys.

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD2
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: COSE WG

Change controller: IETF

## CoAP Content-Formats Registry {#content-format}

IANA is requested to add entries for "application/c509-pubkey+cbor" to the "CoAP Content-Formats" registry in the registry group "Constrained RESTful Environments (CoRE) Parameters".

~~~~~~~~~~~
+----------------------+---------+-----------+-------+------------+
| Content              | Content | Media     | ID    | Reference  |
| Format               | Coding  | Type      |       |            |
+======================+=========+===========+=======+============+
| application/         | -       | [[link    | TBD3  | [[this     |
| c509-pubkey+cbor     |         | to x.y]]  |       | document]] |
+----------------------+---------+-----------+-------+------------+
~~~~~~~~~~~
{: #tab-format-ids title="CoAP Content-Format IDs"}

--- back

# Message Flow Diagrams {#flows}

## caps {#flow-caps}

~~~aasvg
EST Client                                 EST Server
  |                                            |
  | Method: GET                                |
  | Request target: /.well-known/cest/<p>/caps |
  |------------------------------------------->|
  |                                            |
  | Status: 200 OK                             |
  | Media type: text/plain                     |
  |                                            |
  | cacert                                     |
  | cacerts                                    |
  | crlinfo                                    |
  | crl                                        |
  | kemchall                                   |
  | simpleenroll                               |
  | simplereenroll                             |
  |                                            |
  |<-------------------------------------------|
  |                                            |
~~~
{: #fig-caps title="caps message flow"}

## cacert {#flow-cacert}

~~~aasvg
EST Client                                    EST Server
  |                                               |
  | Method: GET                                   |
  | Request target: /.well-known/cest/<p>/cacert  |
  |---------------------------------------------->|
  |                                               |
  | Status: 200 OK                                |
  | Media type: application/cose-c509-cert+cbor   |
  |                                               |
  | <Base64-encoded C509Certificate>              |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-cacert title="cacert message flow"}

## cacerts {#flow-cacerts}

~~~aasvg
EST Client                                       EST Server
  |                                                    |
  | Method: GET                                        |
  | Request target: /.well-known/cest/<p>/cacerts      |
  |--------------------------------------------------->|
  |                                                    |
  | Status: 200 OK                                     |
  | Media type: application/cose-c509+cbor;usage=chain |
  |                                                    |
  | <Base64-encoded COSE_C509>                         |
  |<---------------------------------------------------|
  |                                                    |
~~~
{: #fig-cacerts title="cacerts message flow"}

## crlinfo {#flow-crlinfo}

~~~aasvg
EST Client                                    EST Server
  |                                               |
  | Method: GET                                   |
  | Request target: /.well-known/cest/<p>/crlinfo |
  |   [?crlnumber=<n>][&crldp=<dp>]               |
  |---------------------------------------------->|
  |                                               |
  | Status: 200 OK                                |
  | Media type: application/c509-crlinfo+cbor     |
  |                                               |
  | <Base64-encoded C509CRLInfo>                  |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-crlinfo title="crlinfo message flow"}

## crl {#flow-crl}

~~~aasvg
EST Client                                   EST Server
  |                                               |
  | Method: GET                                   |
  | Request target: /.well-known/cest/<p>/crl     |
  |   [?crlnumber=<n>][&crldp=<dp>]               |
  |                                               |
  |---------------------------------------------->|
  |                                               |
  |  Status: 200 OK                               |
  |  Media type: application/c509-crl+cbor        |
  |                                               |
  |  <Base64-encoded C509CRL>                     |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-crl title="crl message flow"}

## simpleenroll {#flow-simpleenroll}

~~~aasvg
EST Client                                      EST Server
  |                                                    |
  | [HTTP Basic or Digest auth header,                 |
  |   or TLS client certificate]                       |
  |                                                    |
  | Method: POST                                       |
  | Request target: /.well-known/cest/<p>/simpleenroll |
  | Media type: application/cose-c509-pkcs10+cbor      |
  |                                                    |
  | <Base64-encoded C509CertificationRequest>          |
  |--------------------------------------------------->| Verify PoP,
  |                                                    | Issue C509
  |                                                    | cert
  | Status: 200 OK                                     |
  | Media type: application/cose-c509-cert+cbor        |
  |                                                    |
  | <Base64-encoded C509Certificate>                   |
  |<---------------------------------------------------|
  |                                                    |
~~~
{: #fig-simpleenroll title="simpleenroll message flow"}

## serverkeygen {#flow-serverkeygen}

~~~aasvg
EST Client                                  EST Server
  |                                               |
  | [HTTP Basic or Digest auth header,            |
  |   or TLS client certificate]                  |
  |                                               |
  | Method: POST                                  |
  | Request target:                               |
  |            /.well-known/cest/<p>/serverkeygen |
  | Media type: application/cose-c509-pkcs10+cbor |
  |                                               |
  | <CBOR C509 CSR (no pubkey)>                   |
  |---------------------------------------------->|
  |                                               | Generate
  |                                               | keypair,
  |                                               | Issue C509
  | Status: 200 OK                                | cert, Delete
  | Media type: application/cose-c509-pem+cbor    | key from server
  |                                               | 
  | <Base64-encoded C509PEM>                      |
  |<----------------------------------------------|
  | (key no longer on EST server)                 |
  |                                               |
~~~
{: #fig-serverkeygen title="serverkeygen message flow"}

# Acknowledgements {#acknowledgements}
{:unnumbered}

The authors thank xxx for reviewing and commenting on intermediate versions of the draft.
