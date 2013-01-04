# BrowserID GSS-API Mechanism

## Introduction

The BrowserID GSS mechanism is a GSS-API security mechanism that allows you to use BrowserID-generated assertions for signing in to non-web protocols, such as SMTP, IMAP, SSH, LDAP, CIFS, and NFS. Any protocol that supports GSS-API or SASL and does not require mutual authentication should work.

More information on BrowserID is available at the URL <https://developer.mozilla.org/en-US/docs/persona>.

The GSS BrowserID mechanism imports the [BrowserID spec][BIDSPEC].

[BIDSPEC]: https://github.com/mozilla/id-specs/blob/prod/browserid/index.md "BrowserID specification"
[RFC2743]: http://www.ietf.org/rfc/rfc2743.txt
[RFC3961]: http://www.ietf.org/rfc/rfc3961.txt
[RFC4121]: http://www.ietf.org/rfc/rfc4121.txt
[JWT]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token

Note that "initiator" is the client or user-agent and the "acceptor" is the server or relying party. For consistency, the GSS terms are used below.

## Protocol flow

### Initiator to acceptor

1. The initiator composes an audience URL from the target service name.
2. The initiator composes a set of claims including, if applicable, channel binding information and DH parameters for the security context.
2. The initiator calls BrowserID.internal.get() with the audience URL and asserted claims, to request the browser generate an assertion. (Presently the claims are encoded inside the audience URL.) The browser interaction must be modal with respect to the user's interaction with the application.
3. Once an assertion is generated, the initiator sends it to the acceptor inside a context token of TOK_TYPE_INITIATOR_CONTEXT.
4. The initiator returns GSS_C_CONTINUE_NEEDED to indicate an additional context token is expected from the acceptor.

### Acceptor to initiator

1. The acceptor validates that the token is well formed and contains the correct mechanism OID and token type.
2. The acceptor verifies the backed identity assertion per [BIDSPEC]. In the case of failure, an error token is generated.
3. The acceptor unpacks the GSS claims object from the audience URL and verifies the service name and channel binding. In the case of failure, an error token is generated.
4. If required, the acceptor generates a DH public key using the parameters received from the client.
5. The acceptor generates a response token containing the DH public key and expiry time. The response token is signed using the DH shared secret key.
6. The context root key (CRK) is derived from the DH key and GSS_S_COMPLETE is returned, along with the initiator name from the verified assertion. Other assertion attributes may be made available via GSS_Get_name_attribute().

### Initiator context completion

1. The initiator unpacks the acceptor response token JWT.
2. The DH shared secret is computed from the acceptor's DH public key and is used to verify the JWT.
3. The initiator validates the context expiry time received from the acceptor. Note that this will typically match the assertion lifetime and that message protection services may be used beyond this time.
4. The context root key (CRK) is derived from the DH key and GSS_S_COMPLETE is returned to indicate the user is authenticated and the context is ready for use.

### Fast re-authentication extensions

Fast re-authentication allows a context to be established without acquiring a new BrowserID assertion. Instead an assertion signed with a secret key derived from the initial DH key exchange is used. Re-authentication MUST not succeed beyond the user's certificate expiry time.

#### Ticket generation

If the acceptor supports re-authentication, the following steps are added to the "acceptor to initiator" flow described above.

1. A unique ticket identifier is generated. The acceptor must be able to use this to retrieve the authenticator root key, ticket expiry time, and any other attributes re-authenticated acceptor contexts will need.
2. The acceptor creates a JSON object containing the ticket identifier and expiry time and returns it in the response to the initiator.

The initiator MAY cache such tickets, along with the ARK and expiry time, received from the acceptor in order to re-authenticate to it at a future time.

#### Initiator to acceptor (re-authentication)

1. The initiator looks in its ticket cache for an unexpired ticket for the target. If none is found, the normal authentication flow is performed.
2. The initiator generates an authenticator containing the current time, a random nonce, the ticket identifier, and the target name (audience) and channel bindings requested by the application.
3. The initiator signs the authenticator using its copy of the ARK, using the appropriate hash algorithm associated with the original context (currently HS256 is the only one specified).
4. The authenticator is packed into a "backed" assertion with no certificates.
5. The initiator generates an authenticator session key to be used in verifying the response and in deriving the context root key.
6. The assertion is sent to the acceptor.


#### Acceptor to initiator (re-authentication)

1. The acceptor unpacks the authenticator assertion and looks for a ticket in its cache matching the requested ticket ID. If one is not found, the context establishment fails.
2. The acceptor verifies the authenticator using its copy of the ARK and generates a session key.
3. The acceptor generates a response and signs and returns it.

If the ticket cannot be found, or the authentication fails, the acceptor MAY return an error code in its response, permitting the initiator to recover and fallback to generating a BrowserID assertion. It MAY also include its local timestamp so that the initiator can perform clock skew compensation.

## Protocol elements

### Context tokens

All context establishment tokens are framed per section 1 of [RFC2743].

    GSS-API DEFINITIONS ::=
            BEGIN

            MechType ::= OBJECT IDENTIFIER
            -- representing BrowserID mechanism
            GSSAPI-Token ::=
            -- option indication (delegation, etc.) indicated within
            -- mechanism-specific token
            [APPLICATION 0] IMPLICIT SEQUENCE {
                    thisMech MechType,
                    innerToken ANY DEFINED BY thisMech
                       -- contents mechanism-specific
                       -- ASN.1 structure not required
                    }
            END
            
The innerToken always contains a two octet token ID followed by a [JSON Web Token][JWT]. This document defines the following token IDs:

    TOK_TYPE_INITIATOR_CONTEXT			0xB1 0xD1
    TOK_TYPE_ACCEPTOR_CONTEXT			0xB1 0xD2
    TOK_TYPE_DELETE_CONTEXT				0xB1 0xD3
    
Message protection (confidentiality/wrap) are encoded according to [RFC4121].

**TBD**:

* Do we want to do away with the token ID and wrap everything in JSON?
* The GSS-API framing is only required on the initial context token, but historically many mechanisms use it on all tokens. Should this be revisited?

### Mechanism OIDs

GSS BrowserID is a family of mechanisms, where the last element in the OID arc indicates the [RFC4121] encryption type supported for message protection services. The OID prefix is 1.3.6.1.4.1.5322.24.1.

For example, the OID 1.3.6.1.4.1.5322.24.1.17 defines the browserid-aes128 mechanism.

### Name type OIDs

The name type GSS_BROWSERID_NT_EMAIL_OR_SPN is defined with the OID 1.3.6.1.4.1.5322.24.2.1.

This name may contain an e-mail address or a service principal name:

    char-normal = %x00-2E/%x30-3F/%x41-5B/%x5D-FF
    char-escaped = "\" %x2F / "\" %x40 / "\" %x5C
    name-char = char-normal / char-escaped
    name-string = 1*name-char

    user = name-string
    domain = name-string
    email = user "@" domain

    service-name = name-string
    service-host = name-string
    service-specific = name-string
    service-specifics = service-specific 0*("/" service-specifics)
    spn = service-name ["/" service-host [ "/" service-specifics]]

    name = email / spn

Examples:

* lukeh@padl.com
* host/www.persona.org
* ldap/ldap-1.browserid.org/persona.org

### BrowserID audience encoding

Ideally, BrowserID would support adding arbitrary claims to self-signed assertions. In order to work around this, GSS-specific claims are presently encoded the in the audience URL. The encoding is as follows:

    spn = service-name ["/" service-host [ "/" service-specifics]]
    gss-encoded-claims = base64-encode(gss-claims)
    audience = "urn:x-gss:" son "#" gss-encoded-claims
    
The host name is stripped out from the service principal name; any other components are included in the GSS claims object. An example:

    urn:x-gss:host/browserid.org#eyJkaCI6eyJwIjoibHRJaVFCN21MMWVNbVdzbmtOZmxFdyIsImciOiJBZyIsInkiOiJhWmJ6V1VYRVRWeTEtdVpmX1hGNnB3In19
    
decodes to:

    {"dh":{"p":"ltIiQB7mL1eMmWsnkNflEw","g":"Ag","y":"aZbzWUXETVy1-uZf_XF6pw"}}
    
The service principal name in this case is "host/www.browserid.org".

(It would be preferable to just encode the service principal name in a URN with the "gss:" prefix.)

### GSS-specific assertion claims

These claims are included in the assertion sent to the acceptor and are authenticated by the initiator's private key and certificate chain. In a future specification, these may be present in the assertion directly. Currently they are encoded in the gss-encoded-claims component of the audience URL hostname, as described above.

#### "cbt" (Channel Binding Token)

This contains a channel binding token for binding the GSS context to an outer channel (e.g. see RFC 5929). Its value is the base64 URL encoding of the application-specific data component of the channel bindings passed to GSS_Init_sec_context() or GSS_accept_sec_context().

#### "dh" (Diffie-Hellman key exchange)

These contain DH key parameters for deriving a shared session key with the relying party: "g" contains the generator, "p" the prime, and "y" the public value. All are base64 URL encoded.

The prime length should be an equivalent number of bits to the negotiated [RFC4121] encryption type.

### Response JWT

The response JSON web token is sent from the acceptor to the initiator. In the case of a key successfully being negotiated, it is signed with the shared DH key. The HMAC-SHA256 (HS256) algorithm MUST be supported by implementors of this specification.

If a key is unavailable, then the signature is absent and the value of the "alg" header claim is "none". No signature verification is required in this case.

The JWT may contain the following parameters:

#### now

The current acceptor time, in milliseconds since January 1, 1970. This allows the initiator to compensate for clock differences when generating assertions.

#### dh

This contains a JSON object with a single key, "y", containing the base64 URL encoding of the acceptor's DH public value.

#### exp

This contains the time when the context expires. It MUST not be longer than the user's certificate expiry time.

For compatibility with existing applications, it SHOULD NOT be validated by message protection services such as GSS_Wrap().

#### tkt

This contains a JSON object that may be used for re-authenticating to the acceptor without acquiring an assertion. Its usage is optional.

##### jti

An opaque ticket identifier to be presented in a re-authenticator.

##### exp

The expiry time of the ticket. A recommended value is the user's certificate expiry time. It MUST not be longer than this.

#### gss-maj

This contains a GSS major status code represented as a number. It MUST not be present if the acceptor did not return an error. Its usage is optional.

**TBD** do we really want to return GSS protocol error codes or should we return a string error?

#### gss-min

This contains a GSS minor status code represented as a number. It MUST not be present if the acceptor did not return an error and SHOULD not be present if there is no minor status code for the given major error. Its usage is optional.

If GSSBID_REAUTH_FAILED is received, the initiator SHOULD attempt to send another initial context token containing a fresh assertion.

**TBD** protocol minor status codes

### Key derivation

#### Diffie-Hellman Key (DHK)

This key is the shared secret resulting from the Diffie-Hellman exchange. It is presently used without derivation to sign the acceptor's response token, except in the case of re-authentication when the authenticator session key (ASK) is used instead.

#### Context Root Key (CRK)

The context root key is used for RFC 4121 message protection services, e.g. GSS_Wrap() and GSS_Get_MIC(). It is derived as follows:

    Tn = pseudo-random(DHK, n || "rfc4121-gss-browserid")
    CRK = random-to-key(truncate(L, T0 || T1 || .. || Tn))
    L = random-to-key input size
    
where n is a 32-bit integer in network byte order starting at 0 and incremented to each call to the [RFC3961]pseudo_random operation.

#### Authenticator Root Key (ARK)

The authenticator root key (ARK) is used to sign authenticators used for fast re-authentication. It is derived as follows:

    ARK = HMAC(DHK, "browserid-reauth" || 0x00)

The HMAC hash algorithm for all currently specified [RFC3961] encryption types is SHA256.

#### Authenticator Session Key (ASK)

The authenticator session key (ASK) is used as the context root key for re-authenticated contexts. It is derived as follows:

    iat = 64-bit big-endian timestamp from authenticator
    n = 64-bit nonce from authenticator
    ASK = HMAC(ARK, "browserid-reauth" || iat || n || 0x01)

The HMAC hash algorithm for all currently specified [RFC3961] encryption types is SHA256.

### Naming extensions

The acceptor MAY surface attributes from the assertion and any certificates using GSS_Get_name_attribute(). The URN prefix is "urn:ietf:params:gss:jwt". The acceptor MUST filter any sensitive attributes before returning them to the application.

If a SAML assertion is present in the "saml" parameter of the leaf certificate, it may be surfaced using the URN prefix "urn:ietf:params:gss:federated-saml-attribute".

Attributes from the assertion MUST be marked as unauthenticated unless otherwise validated by the acceptor (e.g. the audience).

Attributes from certificates SHOULD be marked as authenticated.

### Fast re-authentication assertion format

When using fast re-authentication, the initiator sends an assertion containing the following payload:

    iat = milliseconds since January 1, 1970
    n   = 64-bit base64 URL encoded random nonce
    tkt = opaque ticket identifier
    aud = string encoding of service principal name
    cbt = base64 URL encoding of channel binding application-specific data

It MAY also send an expiry time in the "exp" parameter, otherwise it expires 5 minutes from the issue time, or the expiry time of the ticket, whichever is earlier. The ticket expiry time must be cached by the acceptor, along with the subject, issuer, audience, expiry time and ARK of the original assertion. The acceptor may share this cache with the replay cache, although this is an implementation detail.

The fast re-authentication assertion is signed using the authenticator root key.