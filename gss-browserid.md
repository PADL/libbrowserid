# BrowserID GSS-API Mechanism

Luke Howard, PADL Software <<lukeh@padl.com>>
January 2013

## Introduction

The BrowserID GSS mechanism is a GSS-API security mechanism that allows you to use BrowserID-generated assertions for signing in to non-web protocols, such as SMTP, IMAP, SSH, LDAP, CIFS, and NFS. Any protocol that supports GSS-API or SASL and does not require mutual authentication should work.

More information on BrowserID is available at the URL <https://developer.mozilla.org/en-US/docs/persona>.

The GSS BrowserID mechanism imports the [BrowserID spec][BIDSPEC].

[BIDSPEC]: https://github.com/mozilla/id-specs/blob/prod/browserid/index.md "BrowserID specification"
[BIDOVER]: https://developer.mozilla.org/en-US/docs/Persona/Protocol_Overview
[RFC2743]: http://www.ietf.org/rfc/rfc2743.txt
[RFC3961]: http://www.ietf.org/rfc/rfc3961.txt
[RFC4121]: http://www.ietf.org/rfc/rfc4121.txt
[JWT]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
[GSS-REST]: http://www.w3.org/2011/identity-ws/papers/idbrowser2011_submission_16.pdf

Note that "initiator" is the client or user-agent and the "acceptor" is the server or relying party. For consistency, the GSS terms are used below.

## Protocol flow

A brief summary of GSS-API follows, excerpted from [GSS-REST]:
> The GSS-API protocol is quite simple: a client (known as an initiator) sends an initial security context token of a chosen GSS security mechanism to a peer (known as an acceptor), then the two will exchange, synchronously, as many security context tokens as necessary to complete authentication or fail. The specific number of context tokens exchanged varies by security mechanism.
> Once authentication is complete, the initiator and the acceptor will share a security context that includes shared secret session key material, and they may then exchange per-message tokens encrypting and/or authenticating application messages.

A summary of the BrowserID protocol can be found at [BIDOVER]. Essentially it involves:

* A user's browser generates a short-term key pair
* The key pair is signed by the user's identity provider (which has previously verified the user's e-mail address and authenticated them)
* The IdP signs the public key and issues a certificate
* When authenticating to a relying party, the browser generates an "identity assertion" (similar to a Kerberos authenticator), containing the RP domain and an expiration time (generally a few minutes after it was created). The user signs this, and presents both the assertion and the user certificate to the RP.
* The RP verifies this using user's and IdP's public keys (and those of any intermediate certifying parties).

Essentially the GSS mechanism described here bridges these two worlds.


### Initiator to acceptor

1. The initiator composes a set of claims including, if applicable, channel binding information and DH parameters for session key establishment.
2. The initiator composes an audience URL from the target service name and, in the present implementation, the asserted claims.
2. The initiator calls BrowserID.internal.get() to request the browser generate an assertion. The browser interaction must be modal with respect to the user's interaction with the application.
3. Once an assertion is generated, the initiator sends it to the acceptor inside a context token of TOK_TYPE_INITIATOR_CONTEXT.
4. The initiator returns GSS_C_CONTINUE_NEEDED to indicate an additional context token is expected from the acceptor.

### Acceptor to initiator

1. The acceptor validates that the token is well formed and contains the correct mechanism OID and token type.
2. The acceptor verifies the backed identity assertion per [BIDSPEC]: this includes validating the expiry times, audience, certificate chain, and the assertion signature. In the case of failure, an error token is generated and immediately returned.
3. The acceptor unpacks the GSS claims object from the audience URL and verifies the service name component and channel binding. In the case of failure, an error token is generated.
4. If required, the acceptor generates a DH public key using the parameters received from the client.
5. The acceptor generates a response token containing the DH public key and context expiry time. The response token is signed using the DH shared secret key.
6. The context root key (CRK) is derived from the DH key and GSS_S_COMPLETE is returned, along with the initiator name from the verified assertion. Other assertion attributes may be made available via GSS_Get_name_attribute().

### Initiator context completion

1. The initiator unpacks the acceptor response token JWT.
2. The DH shared secret is computed from the acceptor's DH public key and is used to verify the response token.
3. The initiator sets the context expiry time with that received in the response token. If the context has expired, GSS_S_CONTEXT_EXPIRED is returned and context establishment fails.
4. The context root key (CRK) is derived from the DH key and GSS_S_COMPLETE is returned to indicate the user is authenticated and the context is ready for use. No output token is emitted.

### Fast re-authentication extensions

Fast re-authentication allows a context to be established without acquiring a new BrowserID assertion. Instead an assertion signed with a secret key derived from the initial DH key exchange is used. Re-authentication MUST not succeed beyond the user's certificate expiry time.

#### Ticket generation

If the acceptor supports re-authentication, the following steps are added to the "acceptor to initiator" flow described above.

1. A unique ticket identifier is generated. The acceptor must be able to use this to retrieve the authenticator root key, ticket expiry time, and any other attributes re-authenticated acceptor contexts will need.
2. The acceptor creates a JSON object containing the ticket identifier and expiry time and returns it in the response to the initiator.

The initiator MAY cache such tickets, along with the ARK and expiry time, received from the acceptor in order to re-authenticate to it at a future time.

#### Initiator to acceptor (re-authentication)

1. The initiator looks in its ticket cache for an unexpired ticket for the target (acceptor). If none is found, the normal authentication flow is performed.
2. The initiator generates an authenticator containing: an expiry time a few minutes from the current time, a random nonce, the ticket identifier, and the target name (audience) and channel bindings requested by the application.
3. The initiator signs the authenticator using its copy of the ARK, using the appropriate hash algorithm associated with the original context (only HS256 is presently specified).
4. The authenticator is packed into a "backed" assertion with no certificates.
5. The initiator generates an authenticator session key to be used in verifying the response and in deriving the context root key.
6. The assertion is sent to the acceptor.

#### Acceptor to initiator (re-authentication)

1. The acceptor unpacks the authenticator assertion and looks for a ticket in its cache matching the requested ticket ID.
2. The acceptor validates that the ticket and authenticator have not expired.
3. The acceptor verifies the authenticator using its copy of the ARK.
4. The acceptor generates the ASK and derived the CRK from this.
3. The acceptor generates a response and signs and returns it.

If the ticket cannot be found, or the authentication fails, the acceptor MAY return an error code in its response, permitting the initiator to recover and fallback to generating a BrowserID assertion. It MAY also include its local timestamp so that the initiator can perform clock skew compensation.

## Protocol elements

### Context tokens

The initial context token is framed per section 1 of [RFC2743].

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
            
Subsequent context tokens do not have this framing, i.e. they consist only of the innerToken.

The innerToken always contains a two octet token ID followed by a [JSON Web Token][JWT]. This document defines the following token IDs:

    TOK_TYPE_INITIATOR_CONTEXT			0xB1 0xD1
    TOK_TYPE_ACCEPTOR_CONTEXT			0xB1 0xD2
    TOK_TYPE_DELETE_CONTEXT				0xB1 0xD3
    
Message protection (confidentiality/wrap) are framed according to [RFC4121].

**TBD**:

* Do we want to do away with the token ID and wrap everything in JSON, or assume that initiator tokens are always backed assertions and acceptor responses always JWTs? The latter would be simple but is not particularly flexible for future evolution.

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

The mechanism supports both GSS_C_NT_USER_NAME and GSS_C_NT_HOSTBASED_SERVICE. GSS_C_NT_USER_NAME is used directly, and GSS_C_NT_HOSTBASED_SERVICE is transformed by replacing the "@" replaced by a "/".

A default domain may be appended when importing names of type GSS_C_NT_USER_NAME.

### BrowserID audience encoding

Ideally, BrowserID would support adding arbitrary claims to self-signed assertions. As this is presently not possible, GSS-specific claims are currently encoded the in the audience URL. The encoding is as follows:

    spn = service-name ["/" service-host [ "/" service-specifics]]
    gss-encoded-claims = base64-encode(gss-claims)
    audience = "urn:x-gss:" spn "#" gss-encoded-claims
    
The host name is stripped out from the service principal name; any other components are included in the GSS claims object. An example:

    urn:x-gss:host/www.browserid.org#eyJkaCI6eyJwIjoibHRJaVFCN21MMWVNbVdzbmtOZmxFdyIsImciOiJBZyIsInkiOiJhWmJ6V1VYRVRWeTEtdVpmX1hGNnB3In19
    
decodes to:

    {"dh":{"p":"ltIiQB7mL1eMmWsnkNflEw","g":"Ag","y":"aZbzWUXETVy1-uZf_XF6pw"}}
    
The service principal name in this case is "host/www.browserid.org".

### BrowserID invocation

The GSS mechanism should call BrowserID.internal.get() with the composed audience URL and a callback that will return the assertion to the mechanism. As the GSS-API is synchronous, the mechanism implementation must block until the callback is invoked (strictly, this is an API and not a protocol issue).

The siteName option SHOULD be set to the hostname component of the service principal name.

The silent option MAY be used if the GSS credential is bound to a name.

### Validation

#### Expiry times

The expiry and, if present, issued-at and not-before times of all elements in a backed assertion, MUST be validated. This applies equally to re-authentication assertions, public key assertions, and the entire certificate chain. If the expiry time is absent, the issued-at time MUST be present, and the JWT implicitly expires a configurable interval (typically five minutes) after the issued-at time.

The GSS context lifetime MUST NOT exceed the lifetime of the user's certificate.

The lifetime of a re-authentication ticket MUST NOT exceed the lifetime of the user's certificate. The acceptor MUST validate the ticket expiry time when performing re-authentication.

Message protections services such as GSS_Wrap() SHOULD be available beyond the GSS context lifetime for maximum application compatibility.

**TODO** notes about clock skew recovery

#### Audience

If the credential passed to GSS_Accept_sec_context() is not for the identity GSS_C_NO_NAME, then it MUST match the unpacked audience (that is, the audience without the URN prefix and encoded claims dictionary).

**TODO** notes about service principal name aliases

#### Channel bindings

If the acceptor passed in channel bindings to GSS_Accept_sec_context(), the assertion MUST contain a matching channel binding claim. (Only the application_data component is validated.) 

#### Signatures

Signature validation on assertions is the same as for the web usage of BrowserID, with the addition that re-authentication assertions may be signed with a symmetric key.

#### Replay cache

The accept SHOULD maintain a cache of received assertions in order to guard against replay attacks.

### GSS-specific assertion claims

These claims are included in the assertion sent to the acceptor and are authenticated by the initiator's private key and certificate chain.

In a future specification, these may be present in the assertion directly. Currently they are encoded in the gss-encoded-claims component of the audience URL hostname, as described above.

#### "cbt" (Channel Binding Token)

This contains a channel binding token for binding the GSS context to an outer channel (e.g. see RFC 5929). Its value is the base64 URL encoding of the application-specific data component of the channel bindings passed to GSS_Init_sec_context() or GSS_accept_sec_context().

#### "dh" (Diffie-Hellman key exchange)

These contain DH key parameters for deriving a shared session key with the relying party: "g" contains the generator, "p" the prime, and "y" the public value. All are base64 URL encoded.

The prime length should be an equivalent number of bits to the negotiated [RFC4121] encryption type.

### Response JWT

The response JSON web token is sent from the acceptor to the initiator. In the case of a key successfully being negotiated, it is signed with the shared DH key. The HMAC-SHA256 (HS256) algorithm MUST be supported by implementors of this specification.

If a key is unavailable, then the signature is absent and the value of the "alg" header claim is "none". No signature verification is required in this case.

The JWT may contain the following parameters:

#### iat

The current acceptor time, in milliseconds since January 1, 1970. This allows the initiator to compensate for clock differences when generating assertions.

**TBD** not defined yet how this is to be used

#### dh

This contains a JSON object with a single key, "y", containing the base64 URL encoding of the acceptor's DH public value.

#### exp

This contains the time when the context expires.

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

The key derivations import the following:

    browserid-derive-key(K, salt) = HMAC(K, "BrowserID" || salt || 0x01)

The HMAC hash algorithm for all currently specified key lengths is SHA256.

#### Diffie-Hellman Key (DHK)

This key is the shared secret resulting from the Diffie-Hellman exchange. It must be at least as many bits as the key size of the negotiated [RFC3961] encryption type.

#### Context Root Key (CRK)

The context root key is used for RFC 4121 message protection services, e.g. GSS_Wrap() and GSS_Get_MIC(). It is derived as follows:

    Tn = pseudo-random(DHK, n || "rfc4121-gss-browserid")
    CRK = random-to-key(truncate(L, T0 || T1 || .. || Tn))
    L = random-to-key input size
    
where n is a 32-bit integer in network byte order starting at 0 and incremented to each call to the [RFC3961]pseudo_random operation.

In the re-authentication case, the ASK is used instead of the DHK.

It is also used directly (as in, with HMAC rather than get_mic) to sign the acceptor's response token.

#### Authenticator Root Key (ARK)

The authenticator root key (ARK) is used to sign authenticators used for fast re-authentication. It is derived as follows:

    ARK = browserid-derive-key(DHK, "ARK")

#### Authenticator Session Key (ASK)

The authenticator session key (ASK) is used instead of the DHK for re-authenticated contexts. It is derived as follows:

    ap = authenticator encoded as JWT
    ASK = browserid-derive-key(ARK, ap)

**TODO** would it be more conservative to only mix in the time and nonce from the authenticator rather than the entire encoded authenticator?

#### GSS PRF

This follows [RFC4402](http://www.ietf.org/rfc/rfc4402.txt).

### Naming extensions

The acceptor MAY surface attributes from the assertion and any certificates using GSS_Get_name_attribute(). The URN prefix is "urn:ietf:params:gss:jwt". The acceptor MUST filter any sensitive attributes before returning them to the application.

If a SAML assertion is present in the "saml" parameter of the leaf certificate, it may be surfaced using the URN prefix "urn:ietf:params:gss:federated-saml-attribute".

Attributes from the assertion MUST be marked as unauthenticated unless otherwise validated by the acceptor (e.g. the audience).

Attributes from certificates SHOULD be marked as authenticated.

### Fast re-authentication assertion format

When using fast re-authentication, the initiator sends an assertion containing the following payload:

    iat = issue time
    n   = 64-bit base64 URL encoded random nonce
    tkt = opaque ticket identifier
    aud = string encoding of service principal name
    cbt = base64 URL encoding of channel binding application-specific data

The re-authentication assertion has an implicit expiry after the issue time (see notes above).

The ticket expiry time must be cached by the acceptor, along with the subject, issuer, audience, expiry time and ARK of the original assertion. The acceptor may share this cache with the replay cache, although this is an implementation detail.

The fast re-authentication assertion is signed using the authenticator root key.