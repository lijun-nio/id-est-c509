---
v: 3

title: "EST for C509 Certificates"
docname: draft-liao-ace-est-c509-03
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
  RFC9148:
  RFC7250:
  RFC8949:
  RFC9277:
  RFC9810:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.liao-cose-c509-revocation:
  NIST.SP.800-227:
    target: https://doi.org/10.6028/NIST.SP.800-227
    title: Recommendation for Key-Encapsulation Mechanisms
    seriesinfo:
      "NIST": "Special Publication 800-227"
    author:
      -
        ins: G. Alagic
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: D. Moody
      -
        ins: A. Roginsky
      -
        ins: H. Silberg
      -
        ins: N. Waller
    date: September 2025


informative:
  RFC2986:

--- abstract

This document defines Enrollment over Secure Transport (EST) protocol operations over HTTPS and secure CoAP for use with C509 certificates. The operations specified in this document support CA certificate distribution, C509 certificate enrollment, C509 certificate re-enrollment, and server-side key generation using C509 certificates. This document also defines operations for Certificate Revocation List (CRL) distribution.

--- middle

# Introduction {#intro}

Enrollment over Secure Transport (EST) {{RFC7030}} defines HTTPS-based operations for X.509 {{RFC5280}} certificate enrollment and CA certificate distribution.  Payloads are DER-encoded and wrapped in CMS (Cryptographic Message Syntax, {{RFC5652}}) structures.  C509 {{I-D.ietf-cose-cbor-encoded-cert}} defines a compact, CBOR-encoded alternative to DER X.509 certificates.  C509 certificates are substantially smaller.

Although C509 was developed with constrained devices in mind, its benefits extend to unconstrained devices operating over low-bandwidth links and to large-scale deployments.  Smaller, CBOR-encoded certificates reduce bandwidth and storage requirements, accelerate TLS handshakes, and lower parsing and serialization overhead even on powerful endpoints; because C509 does not use ASN.1/DER, implementations can avoid complex ASN.1 parsing code, which reduces code size and complexity and lowers the attack surface for certificate parsing libraries.  In complex systems (for example, connected cars) that contain diverse device classes—microcontrollers, sensor chips, and SoCs—using a common certificate format wherever practical simplifies integration and provisioning.  Using C509 consistently across device classes simplifies provisioning, interoperability, and over-the-air updates, and can reduce overall operational costs and latency.

This document defines EST operations that carry C509 objects in place of DER X.509 objects, following the same secure transport and URI path structure as {{RFC7030}} and {{RFC9148}}.

A key property of this design is that EST clients do not require a CBOR parser or generator:

- For non-KEM-only key types, the C509 CSR is typically pre-provisioned as an opaque binary blob by the device manufacturer or a provisioning tool; the EST client sends it verbatim as the POST body of `simpleenroll` / `sen` or `simplereenroll` / `sren` without interpreting its contents.
- For KEM-only key types, the EST client needs to communicate with the key device to get the public key (`C509PublicKey`) and the certification request (`C509CertificationRequest`) after receiving the KEM challenge object (`C509KemChall`) from the EST server; in this case, the EST client considers the `C509PublicKey`, `C509KemChall`, and `C509CertificationRequest` opaque binary blobs.

- For all key types, the C509 certificate (and private key in the operation `serverkeygen` / `skc`) returned in the response is stored directly to persistent memory without parsing.  This property makes the EST client implementation extremely lightweight.

This document uses `C509CertificationRequest` as defined in {{I-D.ietf-cose-cbor-encoded-cert}} as the C509 Certificate Signing Request (C509 CSR) format.  An EST client uses a C509 CSR to request issuance of a C509 certificate from an EST server.

The operations for EST over HTTPS used in this document are (those wit `new` marked are new operations defined in this document) in {{tab-ops-https-overview}}, and for EST over CoAP in {{tab-ops-coaps-overview}}.

~~~~~~~~~~~
+==========+===+=============+==============+===================+
| Opera-   | M | Description |  Request     | Response          |
| tion     | / |             |  Media Type  | Media Type        |
|          | O |             |              |                   |
+==========+===+=============+==============+===================+
| caps     | M | Capability  | (none)       | text/plain;       |
| (new)    |   | discovery   |              | charset=utf-8     |
+----------+---+-------------+--------------+-------------------+
| cacerts  | M | CA          | (none)       | - application/    |
|          |   | certificate |              |   cose-c509+cbor  |
|          |   | retrieval   |              | - application/    |
|          |   |             |              |   cose-c509+cbor, |
|          |   |             |              |   usage=chain     |
|          |   |             |              | - cose-c509-cert  |
|          |   |             |              |   +cbor           |
+----------+---+-------------+--------------+-------------------+
| crli     | O | CRL         | (none)       | application/      |
| (new)    |   | metadata    |              | c509-crlinfo+cbor |
|          |   | retrieval   |              |                   |
+----------+---+-------------+--------------+-------------------+
| crl      | O | CRL         | (none)       | application/      |
| (new)    |   | retrieval   |              | c509-crl+cbor     |
+----------+---+-------------+--------------+-------------------+
| csr      | O | CSR         | (none)       | application/      |
| attrs    |   | attributes  |              | cose-c509-        |
|          |   | retrieval   |              | crtemplate+cbor   |
+----------+---+-------------+--------------+-------------------+
| kemc     | O | KEM         | application/ | application/      |
| (new)    |   | challenge   | c509-pubkey  | c509-kemchall     |
|          |   | issuance    | +cbor        | +cbor             |
+----------+---+-------------+--------------+-------------------+
| simple   | M | Certificate | application/ | application/      |
| enroll   |   | enrollment  | cose-c509-   | cose-c509-        |
|          |   |             | pkcs10+cbor  | cert+cbor         |
+----------+---+-------------+--------------+-------------------+
| simple   | M | Certificate | application/ | application/      |
| reenroll |   | reenroll-   | cose-c509-   | cose-c509-        |
|          |   | ment        | pkcs10+cbor  | cert+cbor         |
+----------+---+-------------+--------------+-------------------+
| server   | O | Server-side | application/ | application/      |
| keygen   |   | key         | cose-c509-   | cose-c509-        |
|          |   | generation  | pkcs10+cbor  | pem+cbor          |
+----------+---+-------------+--------------+-------------------+
~~~~~~~~~~~
{: #tab-ops-https-overview title="Operations for EST over CoAP/DTLS Used in This Document (M/O: MANDDATORY / OPTIONAL)"}

~~~~~~~~~~~
+===============+================+=====+==========+==========+
| EST over      | Corresponding  | M/O | Request  | Response |
| CoAP/DTLS     | EST over HTTPS |     | Content- | Content- |
| Operation     | Operation      |     | Format   | Format   |
+===============+================+=====+==========+==========+
| (Not Related) | caps           |     |          |          |
+---------------+----------------+-----+----------+----------+
| crts          | cacerts        | M   | (none)   | - TBD    |
|               |                |     |          | - TBD    |
|               |                |     |          | - TBD    |
+---------------+----------------+-----+----------+----------+
| crli (new)    | crli           | O   | (none)   | TBD      |
+---------------+----------------+-----+----------+----------+
| crl (new)     | crl            | O   | (none)   | TBD      |
+---------------+----------------+-----+----------+----------+
| attr          | csrattrs       | O   | (none)   | TBD      |
+---------------+----------------+-----+----------+----------+
| kemc (new)    | kemc           | O   | TBD      | TBD      |
+---------------+----------------+-----+----------+----------+
| sen           | simpleenroll   | M   | TBD      | TBD      |
+---------------+----------------+-----+----------+----------+
| sren          | simplereenroll | M   | TBD      | TBD      |
+---------------+----------------+-----+----------+----------+
| skc           | serverkeygen   | O   | TBD      | TBD      |
+---------------+----------------+-----+----------+----------+
~~~~~~~~~~~
{: #tab-ops-coaps-overview title="Operations for EST over CoAP/DTLS Used in This Document (M/O: MANDDATORY / OPTIONAL)"}

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


# Protocol Design {#protocol-design}

## Client Authentication {#client-auth}

While {{RFC7030}} permits a number of the EST functions to be used without authentication, this document requires that the client MUST be authenticated for all functions, as in {{RFC9148}}. This document require the use of EST to support certificate-based client authentication only, neither HTTP Basic nor Digest authentication (as described in Section 3.2.3 of [RFC7030]) is supported, as in {{RFC9148}.

## Discovery and URIs {#discovery-uris}

In EST over HTTPS, the capabilities of EST server is retrieved by using the operation `caps`.

In EST over CoAP/DTLS, the capabilities is retrieved by sending a GET method to the EST server (as in {{Section 4.1 of RFC9148}}) (TODO: the TBD will be replaced with the real value once the Content-Formats are assigned in {{I-D.ietf-cose-cbor-encoded-cert}} and {{I-D.liao-cose-c509-revocation}}). Linefeeds are included only for readability.

~~~
REQ: GET /.well-known/core?rt=ace.est*

RES: 2.05 Content
</est/crts>;rt="ace.est.crts";ct="TBD TBD TBD",
</est/sen>;rt="ace.est.sen";ct=TBD,
</est/sren>;rt="ace.est.sren";ct=TBD,
</est/att>;rt="ace.est.att";ct=TBD,
</est/skc>;rt="ace.est.skc";ct=TBD,
</est/crli>;rt="ace.est.crli";ct=TBD,
</est/crl>;rt="ace.est.crl";ct=TBD,
</est/kemc>;rt="ace.est.kemc";ct=TBD7
~~~

## EST URL Structure and Path Components {#est-url-structure}

The operations in this document follow the same URI path structure defined in {{RFC7030, Section 3.2.2}} for HTTPS and the corresponding secure CoAP mapping defined in {{RFC9148}}.  Retrieval operations `caps`, `cacerts` / `crts`, `csrattrs` / `att`, `crli`, and `crl` use GET method.

~~~
Method: GET
Request target: /.well-known/est/<operation>
Request target: /.well-known/est/<label>/<operation>
~~~

Enrollment operations `kemc`, `simpleenroll` / `sen`, `simplereenroll` / `sren`, and `serverkeygen` / `skc` use HTTP POST or CoAP POST:

~~~
Method: POST
Request target: /.well-known/est/<operation>
Request target: /.well-known/est/<label>/<operation>
~~~

An EST server MUST return HTTP 405 / CoAP 4.05 (Method Not Allowed) if a client uses POST for a retrieval operation or GET for an enrollment operation.

The optional `<label>` path segment follows {{RFC7030, Section 3.2.2}} for HTTPS and the equivalent path structure in {{RFC9148}} for CoAP: an EST server MAY use an additional path segment before the operation name to distinguish services for multiple CAs and / or certificate profiles.

## Channel Binding {#channel-binding}

Channel binding is OPTIONAL. The challel binding mechanisms specified in {RFC7030} and {{RFC9148} apply.

## Message Binding

The message binding mechanism specified in {{RFC9148, Section 4.4}} applies for CoAP in this document.

## Message Fragmentation

The message fragmentation mechanism specified in {{RFC9148, Section 4.6}} applies for CoAP in this document.

## Delayed Responses {#delayed-responses}

The mechanism for delayed responses specified in {{RFC9148, Section 4.7}} applies for CoAP in this document. And the mechanism with retry-later for the operarions `simpleenroll` and `simplereenroll` specified in {{RFC7030, Section 4.2.3}} applies for HTTP in this document.

## Response Cache {#response-cache}

Successful responses, if will not be changed in the next short period, may include caching metadata:

- For EST over HTTPS, EST servers SHOULD include `ETag`, `Last-Modified`, `Cache-Control`, and `Expires` headers.

- For EST over secure CoAP, EST servers SHOULD include the options `E-Tag` and `Max-Age`.

## CBOR Transfer {#cbor-transfer}

All POST request bodies in this document are CBOR-encoded.  For HTTPS, CBOR-based response bodies are base64-encoded for transport.  For CoAP, CBOR payloads are carried directly in the message body using the relevant CoAP Content-Format.  The CBOR encoding MUST be deterministic as specified in {{RFC8949, Sections 4.2.1 and 4.2.2}}.  Servers MUST NOT include a `Content-Transfer-Encoding` header for CBOR payloads.

The media types used in this document are:

| Media Type | CoAP Content Format | Structure | Defined in |
|:---|:---|:---|:---|
| application/cose-c509-cert+cbor        | TBD  | C509Certificate | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509+cbor             | TBD  | COSE_C509 | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509+cbor;usage=chain | TBD  | COSE_C509 | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509-pkcs10+cbor      | TBD  | C509CertificationRequest | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/c509-pubkey+cbor           | TBD3 | C509PublicKey | this document |
| application/c509-kemchall+cbor         | TBD7 | C509KemChall  | this document |
| application/cose-c509-crtemplate+cbor  | TBD  | C509Certification-RequestTemplate | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/cose-c509-pem+cbor         | TBD  | C509PEM (key + certificate) | {{I-D.ietf-cose-cbor-encoded-cert}} |
| application/c509-crl+cbor              | TBD  | C509CRL     | {{I-D.liao-cose-c509-revocation}} |
| application/c509-crlinfo+cbor          | TBD  | C509CRLInfo | {{I-D.liao-cose-c509-revocation}} |
{: #tab-media-types title="Media Types Used in This Document"}

The `caps` operation returns `text/plain; charset=utf-8` with a list of capability keywords.

# C509 Certification Request (C509 CSR) {#c509-csr}

A C509 CSR is a CBOR-encoded certification request used to request issuance of a C509 certificate.  It is the C509 analogue of the PKCS#10 CSR {{RFC2986}} used in standard EST operations.

This document uses `C509CertificationRequest` as defined in {{I-D.ietf-cose-cbor-encoded-cert, Section 4}}.  An EST client sends a C509 CSR to request certificate issuance or re-enrollment. The media type is `application/cose-c509-pkcs10+cbor`.

For server-side key generation requests ({{skc}}), the EST client does not possess the private key and does not know the public key that the EST server will generate.  In this case, the `subjectPublicKeyAlgorithm` in `TBSCertificationRequest` MUST be set to the integer code for `empty-publickey` (see {{empty-publickey}}) and `subjectPublicKey` MUST be a zero-leght byte string (`h''`).  Because no private/public key is available, no PoP signature can be computed/verified: the `signatureAlgorithm` MUST be set to the `id-alg-unsigned` integer code and `signatureValue` MUST be a zero-length byte string.  EST servers MUST accept C509 CSRs using `empty-publickey` and `id-alg-unsigned` for `serverkeygen` / `skc` requests and MUST NOT verify a PoP signature in this case.

## empty-publickey Algorithm {#empty-publickey}

This document defines a new C509 public key algorithm, `empty-publickey`, to be used exclusively in C509 CSRs for `serverkeygen` / `skc` (server key generation) requests to indicate that no public key is available in the CSR.

The `empty-publickey` algorithm code (TBD1) MUST NOT appear in C509 certificates.  It is only valid in the `subjectPublicKeyAlgorithm` field of `TBSCertificationRequest` when the corresponding `subjectPublicKey` is a zero-length byte string (`h''`).  EST servers MUST reject any C509 CSR using `empty-publickey` in a `simpleenroll` / `sen` or `simplereenroll` / `sren` request.

## CRAttribute C509ChangeSubjectName {#change-subject-name}

The C509ChangeSubjectName for X.509 PKI is defined in {{RFC6402}}. The corresponding definition for C509 certification request is a CBOR-array consisting of a `subject` and a `subjectAlt`. At least one of `subject` and `subjectAlt` MUST NOT be `null`.

~~~~~~~~~~~cddl
C509ChangeSubjectName = [
  subject     C509Name / null,
  subjectAlt  SubjectAltName / null
]
~~~~~~~~~~~
{: sourcecode-name="c509est.cddl"}

This CRAttribute MAY be included in a `simplereenroll` / `sren` request to change the `Subject` field and/or the `SubjectAltName` extension in the newly generated certificate.

## Proof of Possession

`simpleenroll` / `sen` and `simplereenroll` / `sren` MUST verify the PoP signature in the C509 CSR before issuing a certificate.  The `serverkeygen` / `skc` operation does not require PoP verification because the EST server generates the key pair itself.

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

- Challenge issuance: Upon receipt of a KEM public key (`C509PublicKey`) in the `kemc` operation, an EST server returns a CBOR-encoded KEM challenge object (`C509KemChall`) with media type `application/c509-kemchall+cbor`.

~~~~~~~~~~~cddl
C509KemChall = [
  keyId         : bstr,
  encapAlg      : int,
  encapsulation : bstr
]
~~~~~~~~~~~
{: sourcecode-name="c509est.cddl"}

The media type of `C509KemChall` is `application/c509-kemchall+cbor` (see {{iana-c509-kemchall}}); the corresponding CoAP Content-Format is defined in {{content-format}}.  The "magic number" is TBD6, using the reserved CBOR tag 55799 and Content-Format TBD7, as described in {{RFC9277, Section 2.2}}.

In particular (TBD: check consistency with {{NIST.SP.800-227}}):

- `keyId` is the SHA-256 fingerprint of the CBOR-encoded `C509PublicKey`,

- `encapAlg` is the encapsulation algorithm (TBD: define a new registry or reuse a COSE algorithm), and

- `encapsulation` is the KEM ciphertext produced by encapsulating a freshly generated one-time secret key `K` to the client's KEM public key.

The server MUST retain the challenge state (at least `keyId`, `K`, and the lifetime) for the duration of the challenge.

- Client decapsulation and response: The client decapsulates `encapsulation` to recover the one-time secret key `K`.  The client computes a MAC value over the `TBSCertificationRequest` with the key `K`.  The client then submits a follow-up operation as usual.

- Server verification: The server computes the `keyId`, retrieves the challenge state for that `keyId`, and verifies that the state is still within its validity period.  The server then verifies the received MAC value against the `TBSCertificationRequest`.  The server proceeds with certificate issuance as for signature-based PoP.  If verification fails or the challenge has expired, the server MUST reject the request.

Implementations SHOULD use HMAC-SHA256 (with integer value TBD4) by default, unless constrained by the KEM's security requirements.  Servers MUST enforce challenge timeouts and retry limits to mitigate replay and denial-of-service risks.

# EST Operations for Server Capability Discovery {#caps-section}

## caps {#caps}

This operation is only related to EST over HTTPS, but not to EST over CoAP/DTLS.

The `caps` operation allows an EST client to discover which C509-specific operations the EST server supports before invoking them. EST clients and EST servers MUST support `caps`.

### Request {#caps-request}

The EST client sends a GET request for the server's C509 capability list.  No request body is sent.

~~~
Method: GET
HTTP request target: /.well-known/est/<label>/caps
~~~

### Response {#caps-response}

On success, the EST server returns a HTTP 200 response with:

- Media type: `text/plain; charset=utf-8`
- Body: A plain-text list of capability keywords, one keyword per line.  The EST server MUST terminate each line with `<CR><LF>`.  The EST client MUST be able to parse lines terminated by `<CR><LF>`, `<CR>`, or `<LF>`.  Keywords are unquoted and case-insensitive.

The following keywords are defined.  An EST server MUST include a keyword in the `caps` response if and only if it supports the corresponding operation.

| Keyword          | Description |
|:-----------------|:------------|
| `cacerts`        | EST server supports `cacerts` ({{crts}}) |
| `crli`           | EST server supports `crli` ({{crli}}) |
| `crl`            | EST server supports `crl` ({{crl}}) |
| `csrattrs`       | EST server supports `csrattrs` ({{att}}) |
| `kemc`           | EST server supports `kemc` ({{kemc}}) |
| `simpleenroll`   | EST server supports `simpleenroll` ({{sen}}) |
| `simplereenroll` | EST server supports `simplereenroll` ({{sren}}) |
| `serverkeygen`   | EST server supports `serverkeygen` ({{skc}}) |
{: #tab-caps-keywords title="caps Keywords Defined in This Document"}

An EST client that receives an error response to a `caps` request MUST NOT attempt the operations defined in this document.

Successful `caps` responses MAY include caching metadata as specified in {{response-cache}}.

Example response:

~~~
cacerts
crli
crl
csrattrs
kemc
simpleenroll
simplereenroll
serverkeygen
~~~

## csrattrs / att {#att}

The `csrattrs` / `att` operation returns a `C509CertificationRequestTemplate` that an EST client MAY use to construct a C509 CSR.

### Request {#att-request}

The EST client sends a GET request for the CSR template.  No request body is sent.

~~~
Method: GET
HTTP Request target: /.well-known/est/<label>/csrattrs
CoAP Request target: /.well-known/est/<label>/attr
~~~

### Response {#att-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/cose-c509-crtemplate+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A `C509CertificationRequestTemplate` as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

An response code of HTTP 404 / CoAP 4.04 indicates that CSR attributes are not available.

Successful `csrattrs` / `att` responses MAY include caching metadata as specified in {{response-cache}}.

# EST Operations for Distribution of CA Certificates {#ca-certificates}

## cacerts / crts {#crts}

Successful `cacerts` / `crts` responses MAY include caching metadata as specified in {{response-cache}}.

Depending on the `Accept` option, the cacerts / `crts` operation returns different forms of the CA certificates (TODO: the TBD will be replaced with the real value once the Content-Formats are assigned in {{I-D.ietf-cose-cbor-encoded-cert}} and {{I-D.liao-cose-c509-revocation}}):

- `Accept: application/cose-c509-cert` (HTTP) / `Accept=TBD` (CoAP): C509Certificate (a single certificate)

- `Accept: application/cose-c509; usage=chain` (HTTP) / `Accept=TBD` (CoAP): COSE_C509 (certificate chain)

- No Accept or `Accept: application/cose-c509` (HTTP) / `Accept=TBD` (CoAP): COSE_C509 (certificate set (unsorted certificates))

### Request

The EST client sends a GET request for the CA certificate(s).  No request body is sent. The `Accept` option specifies the expected Media-Type / Content-Formats of the response. If an `Accept` Option is not included in the request, the client is not expressing any preference and the server SHOULD choose format TBD for certificate set.

~~~
Method: GET

HTTP request target: /.well-known/est/<label>/cacerts
                     (Accept: <accepted media type>)
CoAP request target: /.well-known/est/<label>/crts
                     (Accept=<accepted Content-Format>)
~~~

### Response

On success, the EST server returns a CoAP 2.05 response with:

- For Request with `Accept: application/cose-c509-cert+cbor` (HTTP) / `Accept=TBD` (CoAP):

  - Media type: application/cose-c509-cert+cbor (HTTP) / Content-Format TBD (CoAP)

  - Body: A `C509Certificate` representing a single certificate.

- For Request with `Accept: application/cose-c509+cbor; usage=chain` (HTTP) / `Accept=TBD` (CoAP):

  - Media type: application/cose-c509+cbor; usage=chain (HTTP) / Content-Format TBD (CoAP)

  - Body: A `COSE_C509` representing an ordered certificate chain.  The first element is the issuing CA certificate; subsequent elements are intermediate and root CA certificates in chain order.

- For Request without `Accept` option or with `Accept: application/cose-c509+cbor` (HTTP) / `Accept=TBD` (CoAP):

  - Media type: application/cose-c509+cbor (HTTP) / Content-Format TBD (CoAP)

  - Body: A `COSE_C509` representing an unordered certificate set.  The first element is the issuing CA certificate; subsequent elements are not sorted. If a Root CA key update applies, the EST server SHOULD include the four "Root CA Key Update" certificates OldWithOld, OldWithNew, NewWithOld, and NewWithNew in the response chain.  These are defined in {{RFC9810, Section 4.4}}.

Successful `cacerts` / `crts` responses MAY include caching metadata as specified in {{response-cache}}.

# EST Operations for Distribution of C509 CRLs {#crl-operations}

The `crli` and `crl` operations provide C509 CRL access.  The C509 CRL format is defined in {{I-D.liao-cose-c509-revocation}}.

## crli {#crli}

The `crli` operation returns metadata about the current C509 CRL for the target CA as a `C509CRLInfo` object without the full revocation list.  This enables an EST client to check whether its locally cached CRL is still current before requesting the full `crl`.  `C509CRLInfo` is defined in {{I-D.liao-cose-c509-revocation}}.

### Request {#crli-request}

The EST client sends a GET request for CRL metadata.  No request body is sent.

~~~
Method: GET
Request target: /.well-known/est/<label>/crli
Request target: /.well-known/est/<label>/crli
                [?crlnumber=<n>][&crldp=<dp>]
~~~

The optional `crlnumber` query parameter carries the decimal representation of the CRL number the client is interested in.  When present, the EST server MUST return the `C509CRLInfo` for the CRL with that exact `crlNumber`.  If no CRL with the requested `crlnumber` is available, the EST server MUST return HTTP status 404 (Not Found).  When `crlnumber` is absent, the server returns the `C509CRLInfo` for the most recent CRL.

The optional `crldp` query parameter carries the CRL Distribution Point identifier.  When present, the EST server MUST return the `C509CRLInfo` for the CRL associated with that distribution point.  When both `crlnumber` and `crldp` are present, the server MUST return the `C509CRLInfo` matching both criteria.

### Response {#crli-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/c509-crlinfo+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A `C509CRLInfo` as defined in {{I-D.liao-cose-c509-revocation}}.

`C509CRLInfo` carries all CRL fields from `C509CRLInfoData` — including `crlType`, `signatureAlgorithm`, `authoritySubject`, `authorityKeyIdentifier`, `crlNumber`, `thisUpdate`, `nextUpdate`, `baseCrlNumber`, and `crlExtensions` — without the `revokedCertsList`.  An EST client can use these fields to compare `crlNumber`, `nextUpdate`, or compute a freshness check against its local cache before deciding whether to download the full `C509CRL` via `crl`.

If no matching CRL is available, the EST server MUST return HTTP 404 / CoAP 4.04 (Not Found).

Successful `crli` responses MAY include caching metadata as specified in {{response-cache}}.

## crl {#crl}

The `crl` operation returns the C509 CRL for the target CA.

### Request {#crl-request}

The EST client sends a GET request for the C509 CRL.  No request body is sent.

~~~
Method: GET
Request target: /.well-known/est/<label>/crl
Request target: /.well-known/est/<label>/crl
                [?crlnumber=<n>][&crldp=<dp>]
~~~

The optional `crlnumber` query parameter carries the decimal representation of the CRL number.  When present, the EST server MUST return the full `C509CRL` with that exact `crlnumber`.  When `crlnumber` is absent, the server returns the most recent CRL.

The optional `crldp` query parameter carries the CRL Distribution Point identifier.  When present, the EST server MUST return the full `C509CRL` for the CRL associated with that distribution point.  When both `crlnumber` and `crldp` are present, the server MUST return the `C509CRL` matching both criteria.

If no matching CRL is available, the EST server MUST return HTTP 404 / CoAP 4.04 (Not Found).

### Response {#crl-response}

On success, the EST server returns a HTTP 200/ CoAP 2.05 response with:

- Media type: `application/c509-crl+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A `C509CRL` as defined in {{I-D.liao-cose-c509-revocation}}.

If no matching CRL is available, the EST server MUST return HTTP 404 / CoAP 4.04 (Not Found).

Successful `crl` responses MAY include caching metadata as specified in {{response-cache}}.

# EST Operations for Certificate Enrollment {#enrollment-ops}

## kemc {#kemc}

The `kemc` operation requests a KEM-based Proof-of-Possession challenge for a submitted C509 public key whose `subjectPublicKeyAlgorithm` is a KEM algorithm.

### Request {#kemc-request}

An authenticated EST client sends a POST request containing a `C509PublicKey` ({{c509pubkey}}) to request a KEM challenge.

~~~
Method: POST
Request target: /.well-known/est/<label>/kemc
Media type: application/c509-pubkey+cbor (HTTP) /
            Content-Format TBD (CoAP)
Body: C509PublicKey
~~~

If the request does not contain a KEM public key, the EST server MUST return HTTP 400 / CoAP 4.00 (Bad Request).  If the server supports KEM PoP for the submitted algorithm, it issues a challenge; otherwise, it MUST return HTTP 501 / CoAP 5.01 (Not Implemented).

### Response {#kemc-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/c509-kemchall+cbor` (HTTP) / Content-Format TBD7 (CoAP)
- Body: A `C509KemChall` ({{pop-kem}}).

A client that receives a `C509KemChall` uses the recovered one-time secret key to produce the PoP MAC and then proceeds with a normal enrollment request (`simpleenroll` / `sen` or `simplereenroll` / `sren`) including the computed MAC in the request (see {{pop-kem}} for the PoP flow). The EST server verifies the MAC using the stored challenge state and issues the certificate on success.


## simpleenroll / sen {#sen}

The `simpleenroll` / `sen` operation requests issuance of a new C509 certificate from the EST server.

### Request {#sen-request}

An authenticated EST client sends a POST request containing a C509 CSR ({{c509-csr}}).

~~~
Method: POST
HTTP Request target: /.well-known/est/<label>/simpleenroll
CoAP Request target: /.well-known/est/<label>/sen
Media type: application/cose-c509-pkcs10+cbor (HTTP) /
            Content-Format TBD (CoAP)
Body: C509CertificationRequest
~~~

The `C509CertificationRequest` MUST include a valid PoP signature.  The EST server MUST verify the PoP signature against the public key in the C509 CSR before issuing a certificate, as required by {{RFC7030, Section 3.4}}.

### Response {#sen-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/cose-c509-cert+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A `C509Certificate` issued for the subject in the C509 CSR, as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

## simplereenroll / sren {#sren}

The `simplereenroll` / `sren` operation renews or rekeys an existing C509 certificate.

### Request {#sren-request}

An authenticated EST client sends a POST request containing a C509 CSR for re-enrollment.  The request Subject field and SubjectAltName extension MUST be identical to the corresponding fields in the certificate being renewed or rekeyed.

The `C509ChangeSubjectName` attribute defined in {{change-subject-name}} MAY be included in the CSR to request that these fields be changed in the new certificate.

~~~
Method: POST
HTTP Request target: /.well-known/est/<label>/simplereenroll
CoAP Request target: /.well-known/est/<label>/sren
Media type: application/cose-c509-pkcs10+cbor (HTTP) /
            Content-Format TBD (CoAP)
Body: C509CertificationRequest
~~~

Re-enrollment processing follows {{RFC7030, Section 4.2.2}}.  The EST server MUST verify the PoP signature in the C509 CSR.

### Response {#sren-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/cose-c509-cert+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A renewed `C509Certificate`, as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

## serverkeygen / skc {#skc}

The `serverkeygen` / `skc` operation requests server-side key generation and returns the generated private key and the issued C509 certificate.

As discussed in {{RFC9148, Section 9}}, transporting private keys generated by the EST server is inherently risky. The use of server-generated private keys increases the risk of digital identity theft. Therefore, implementations SHOULD NOT use EST functions that rely on server-generated private keys.

### Request {#skc-request}

An authenticated EST client sends a POST request containing a C509 CSR.  The `subjectPublicKeyAlgorithm` in the C509 CSR SHOULD be set to `empty-publickey` ({{empty-publickey}}) and `subjectPublicKey` SHOULD be a zero-length byte string (`h''`), because the key pair is generated by the EST server.  The `signatureAlgorithm` SHOULD be the `id-alg-unsigned` integer code and `signatureValue` SHOULD be a zero-length byte string.  EST servers MUST accept C509 CSRs that use `empty-publickey` and `id-alg-unsigned` for `serverkeygen` / `skc` and MUST NOT verify a PoP signature in this case.

~~~
Method: POST
HTTP Request target: /.well-known/est/<label>/serverkeygen
CoAP Request target: /.well-known/est/<label>/skc
Media type: application/cose-c509-pkcs10+cbor (HTTP) /
            Content-Format TBD (CoAP)
Body: C509CertificationRequest
~~~

### Response {#skc-response}

On success, the EST server returns a HTTP 200 / CoAP 2.05 response with:

- Media type: `application/cose-c509-pem+cbor` (HTTP) / Content-Format TBD (CoAP)
- Body: A `C509PEM`.

The `C509CertData` field in the `C509PEM` MUST contain only the issued C509 certificate for the generated key pair.

The EST server SHOULD delete the private key from its storage as soon as the response has been transmitted successfully, unless the deployment policy requires retention for key escrow or disaster recovery (see {{security}}).  The private key is protected only by the TLS channel; no additional encryption is applied.

# Security Considerations {#security}

The security requirements of {{RFC7030}} apply in full to all operations defined in this document.

## Transport Security

All operations defined in this document MUST be carried out over HTTPS (HTTP over TLS) or secure CoAP (CoAP over DTLS) as required by {{RFC7030, Section 3}} and {{RFC9148}}.  Implementations MUST NOT fall back to plain HTTP or unsecured CoAP.

EST clients and servers SHOULD use C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}} for TLS or DTLS authentication when both peers support C509.  This enables end-to-end C509 usage, including the handshake itself, and reduces size and parsing overhead consistently.  EST servers SHOULD continue to accept X.509 certificates {{RFC5280}} for TLS or DTLS client authentication for interoperability with clients that do not yet support C509.

### TLS Certificate Type Negotiation

When C509 certificates are used for TLS authentication, the client and server negotiate the certificate type using the `server_certificate_type` and `client_certificate_type` TLS extensions as defined in {{RFC7250}}.

### Client Authentication

All operations MUST require client authentication.

## Server Key Generation

The `skc` operation delivers a generated private key to the EST client over TLS.  EST servers SHOULD delete the private key after successful transmission.  EST clients MUST store the key material securely immediately upon receipt.

As discussed in {{RFC9148, Section 9}}, transporting private keys generated by the EST server is inherently risky. The use of server-generated private keys increases the risk of digital identity theft. Therefore, implementations SHOULD NOT use EST functions that rely on server-generated private keys.

## C509 Certificate Validation

EST clients MUST validate received C509 certificates against an independently configured trust anchor according to {{I-D.ietf-cose-cbor-encoded-cert}}.  The trust model for C509 certificates differs from classical X.509 certificate chain validation when C509 is used in the HyPKI trust architecture; in that case, validation uses the cosigner-signed Merkle tree or signed allowlist rather than a certificate chain.

# IANA Considerations {#iana}

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
| Comments | Exclusively for use in `subjectPublicKeyAlgorithm` of a `TBSCertificationRequest` for server-side key generation (`serverkeygen` / `skc`).  MUST NOT appear in C509 certificates. |
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
|       | attributeValue:  C509ChangeSubjectName                    |
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

Author: ACE WG

Change controller: IETF

### Media Type application/c509-kemchall+cbor {#iana-c509-kemchall}

When the `application/c509-kemchall+cbor` media type is used, the payload is a `C509KemChall` structure.

Type name: application

Subtype name: c509-kemchall+cbor

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary

Security considerations: See the Security Considerations section of [[this document]].

Interoperability considerations: N/A

Published specification: [[this document]]

Applications that use this media type: Applications that employ C509 KEM challenges.

Fragment identifier considerations: N/A

Additional information:

* Deprecated alias names for this type: N/A
* Magic number(s): TBD6
* File extension(s): .c509
* Macintosh file type code(s): N/A

Person & email address to contact for further information: iesg@ietf.org

Intended usage: COMMON

Restrictions on usage: N/A

Author: ACE WG

Change controller: IETF

## CoAP Content-Formats Registry {#content-format}

IANA is requested to add entries for `application/c509-pubkey+cbor` and `application/c509-kemchall+cbor` to the "CoAP Content-Formats" registry in the registry group "Constrained RESTful Environments (CoRE) Parameters".

~~~~~~~~~~~
+----------------------+---------+-----------+-------+------------+
| Content              | Content | Media     | ID    | Reference  |
| Format               | Coding  | Type      |       |            |
+======================+=========+===========+=======+============+
| application/         | -       | [[link    | TBD3  | [[this     |
| c509-pubkey+cbor     |         | to x.y]]  |       | document]] |
+----------------------+---------+-----------+-------+------------+
| application/         | -       | [[link    | TBD7  | [[this     |
| c509-kemchall+cbor   |         | to x.y]]  |       | document]] |
+----------------------+---------+-----------+-------+------------+
~~~~~~~~~~~
{: #tab-format-ids title="CoAP Content-Format IDs"}

--- back

# Message Flow Diagrams of EST over HTTPS Operations {#flows-http}

## caps {#flow-caps-http}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | Method: GET                                  |
  | Request target: /.well-known/est/<p>/caps    |
  |--------------------------------------------->|
  |                                              |
  | Status: 200 OK                               |
  | Media type: text/plain;charset=utf-8         |
  |                                              |
  | <CR-LF seperated list of supported           |
  |  operations>                                 |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-http title="HTTP cacerts message flow"}

## cacerts for single CA certificate {#flow-crts-single-http}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | Method: GET                                  |
  | Request target: /.well-known/est/<p>/cacerts |
  | Accept: application/cose-c509-cert           |
  |--------------------------------------------->|
  |                                              |
  | Status: 200 OK                               |
  | Media type: application/cose-c509+cbor       |
  |                                              |
  | <Base64-encoded COSE_C509>                   |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-single-http title="Message flow of EST over HTTPS operation cacerts for single CA certificate"}

## cacerts for CA certificate set {#flow-crts-set-http}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | Method: GET                                  |
  | Request target: /.well-known/est/<p>/cacerts |
  |--------------------------------------------->|
  |                                              |
  | Status: 200 OK                               |
  | Media type: application/cose-c509+cbor       |
  |                                              |
  | <Base64-encoded COSE_C509>                   |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-set-http title="Message flow of EST over HTTPS operation cacerts for CA certificate set"}

## cacerts for CA certificate chain {#flow-crts-chain-http}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | Method: GET                                  |
  | Request target: /.well-known/est/<p>/cacerts |
  | Accept: application/cose-c509; usage=chain   |
  |--------------------------------------------->|
  |                                              |
  | Status: 200 OK                               |
  | Media type: application/cose-c509+cbor       |
  |                                              |
  | <Base64-encoded COSE_C509>                   |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-chain-http title="Message flow of EST over HTTPS cacerts for CA certificate chain"}

## crli {#flow-crli-http}

~~~aasvg
EST Client                                    EST Server
  |                                               |
  | Method: GET                                   |
  | Request target: /.well-known/est/<p>/crli     |
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
{: #fig-crli-http title="Message flow of EST over HTTPS operation crli"}

## crl {#flow-crl-http}

~~~aasvg
EST Client                                   EST Server
  |                                               |
  | Method: GET                                   |
  | Request target: /.well-known/est/<p>/crl      |
  |   [?crlnumber=<n>][&crldp=<dp>]               |
  |---------------------------------------------->|
  |                                               |
  |  Status: 200 OK                               |
  |  Media type: application/c509-crl+cbor        |
  |                                               |
  |  <Base64-encoded C509CRL>                     |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-crl-http title="Message flow of EST over HTTPS operation crl"}

## kemc {#flow-kemc-http}

~~~aasvg
EST Client                                 EST Server
|                                               |
| [TLS client certificate]                      |
|                                               |
| Method: POST                                  |
| Request target: /.well-known/est/<p>/kemc     |
| Media type: application/c509-pubkey+cbor      |
|                                               |
| <Base64-encoded C509PublicKey>                |
|---------------------------------------------->|
|                                               |
|                                               |
| Status: 200 OK                                |
| Media type: application/c509-kemchall+cbor    |
|                                               |
| <Base64-encoded C509KemChall>                 |
|<----------------------------------------------|
|                                               |
~~~
{: #fig-kemc-http title="Message flow of EST over HTTPS operation kemc"}

## simpleenroll {#flow-sen-htt}

~~~aasvg
EST Client                                 EST Server
  |                                               |
  | [TLS client certificate]                      |
  |                                               |
  | Method: POST                                  |
  | Request target: /.well-known/est/<p>          |
  |                   /simpleenroll               |
  | Media type: application/cose-c509-pkcs10+cbor |
  |                                               |
  | <Base64-encoded C509CertificationRequest>     |
  |---------------------------------------------->| Verify PoP,
  |                                               | Issue C509
  |                                               | cert
  | Status: 200 OK                                |
  | Media type: application/cose-c509-cert+cbor   |
  |                                               |
  | <Base64-encoded C509Certificate>              |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-sen-http title="Message flow of EST over HTTPS operation simpleenroll"}

## simplereenroll {#flow-sren-htt}

~~~aasvg
EST Client                                 EST Server
|                                               |
| [TLS client certificate]                      |
|                                               |
| Method: POST                                  |
| Request target: /.well-known/est/<p>          |
|                   /simplereenroll             |
| Media type: application/cose-c509-pkcs10+cbor |
|                                               |
| <Base64-encoded C509CertificationRequest>     |
|---------------------------------------------->| Verify PoP,
|                                               | Issue C509
|                                               | cert
| Status: 200 OK                                |
| Media type: application/cose-c509-cert+cbor   |
|                                               |
| <Base64-encoded C509Certificate>              |
|<----------------------------------------------|
|                                               |
~~~
{: #fig-sren-http title="Message flow of EST over HTTPS operation simplereenroll"}

## serverkeygen {#flow-skc-http}

~~~aasvg
EST Client                                  EST Server
  |                                               |
  | [TLS client certificate]                      |
  |                                               |
  | Method: POST                                  |
  | Request target: /.well-known/est/<p>          |
  |                   /serverkeygen               |
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
{: #fig-skc-http title="Message flow of EST over HTTPS operation serverkeygen"}

# Message Flow Diagrams of EST over CoAP/DTLS Operations {#flows-coap}

## cacerts for single CA certificate {#flow-crts-single-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | GET example.com/est/<p>/cacerts              |
  | (Accept: TBD)                                |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509Certificate  |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-single-coap title="Message flow of EST over CoAP/DTLS operation cacerts for single CA certificate"}

## cacerts for CA certificate set {#flow-crts-set-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | Method: GET                                  |
  | GET example.com/est/<p>/cacerts              |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded COSE_C509        |
  |   (certificate set) in binary format }       |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-set-coap title="Message flow of EST over CoAP/DTLS operation cacerts for CA certificate set"}

## cacerts for CA certificate chain {#flow-crts-chain-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | GET example.com/est/<p>/cacerts              |
  | (Accept: TBD)                                |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded COSE_C509        |
  |   (certificate chain) in binary format }     |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crts-chain-coap title="Message flow of EST over CoAP/DTLS operation cacerts for CA certificate chain"}

## crli {#flow-crli-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | GET example.com/est/<p>/crli                 |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509CRLInfo      |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crli-coap title="Message flow of EST over CoAP/DTLS operation crli"}

## crl {#flow-crl-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | GET example.com/est/<p>/crl                  |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509CRL          |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-crl-coap title="Message flow of EST over CoAP/DTLS operation crl"}

## kemc {#flow-kemc-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | POST example.com/est/<p>/kemc                |
  | (Content-Format: TBD)                        |
  | { payload with CBOR-encoded C509PublicKey    |
  |   in binary format }                         |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509KemChall     |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-kemc-coap title="Message flow of EST over CoAP/DTLS operation kemc"}

## sen {#flow-sen-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | POST example.com/est/<p>/sen                 |
  | (Content-Format: TBD)                        |
  | { payload with CBOR-encoded                  |
  |  C509CertificationRequest in binary format } |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509Certificate  |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-sen-coap title="Message flow of EST over CoAP/DTLS operation sen"}

## sren {#flow-sren-coap}

~~~aasvg
EST Client                                  EST Server
  |                                              |
  | POST example.com/est/<p>/sren                |
  | (Content-Format: TBD)                        |
  | { payload with CBOR-encoded                  |
  |  C509CertificationRequest in binary format } |
  |--------------------------------------------->|
  |                                              |
  | 2.05 Content (Content-Format: TBD)           |
  | { payload with CBOR-encoded C509Certificate  |
  |   in binary format }                         |
  |<---------------------------------------------|
  |                                              |
~~~
{: #fig-sren-coap title="Message flow of EST over CoAP/DTLS operation sren"}

## skc {#flow-skc-coap}

~~~aasvg
EST Client                                   EST Server
  |                                               |
  | POST example.com/est/<p>/skc                  |
  | (Content-Format: TBD)                         |
  | { payload with CBOR-encoded                   |
  |   C509CertificationRequest in binary format } |
  |---------------------------------------------->|
  |                                               |
  | 2.05 Content (Content-Format: TBD)            |
  | { payload with CBOR-encoded C509PEM           |
  |   in binary format }                          |
  |<----------------------------------------------|
  |                                               |
~~~
{: #fig-skc-coap title="Message flow of EST over CoAP/DTLS operation skc"}

# Acknowledgements {#acknowledgements}
{:unnumbered}

The authors thank xxx for reviewing and commenting on intermediate versions of the draft.

# Change log
{:unnumbered}

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

## Since draft-liao-ace-est-c509-02
{:numbered="false"}

- Use both long name and short name of operations.

- Add message flows for the cacerts / crts operation to retrieve single CA certificate, and CA certificate chain.

- Add message flows for EST over CoAP/DTLS.

- Editorial changes.

## Since draft-liao-ace-est-c509-01
{:numbered="false"}

- Add EST of C509 certificate over secure CoAP (updates {{RFC9148}}).

- Use short operation names defined in {{RFC9148}} to replace the long names defined in {{RFC7030}}.
