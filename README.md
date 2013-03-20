# BrowserID GSS/SASL Mechanism

The BrowserID GSS mechanism is a plugin for the GSS-API that allows you to use
BrowserID-generated assertions for signing in to non-web protocols, such as
SMTP, IMAP, SSH, LDAP, CIFS, and NFS. Any protocol that supports GSS-API or
SASL should work (protocols that require mutual authentication will need a
certificate to be configured on the server side).

More information on BrowserID is available at the URL
<https://developer.mozilla.org/en-US/docs/persona>.

## Architecture

The BrowserID GSS mechanism is split into two parts: libbrowserid, which is a
(more or less) general-purpose library for generating and verifying BrowserID
assertions; and mech\_browserid, which is the actual GSS mechanism (based on
the Moonshot code).

If you would just like to build libbrowserid, then execute configure with the
--disable-gss-mech flag. This will remove Kerberos as a dependency. Sample code
for using it in a non-GSS application can be found in sample.

Information on the BrowserID GSS protocol can be found here:

<http://tools.ietf.org/html/draft-howard-gss-browserid>

Essentially the protocol is the same as for web-based BrowserID, with a couple of
exceptions. First, the assertion is emitted as a GSS context token, to be sent
within the application protocol (rather than being posted to a web server).
Secondly, the assertion includes extra properties which allow key agreement and
channel binding verification. There is also a fast re-authentication mode avoids
having to acquire a new certificate-signed assertion for a service to which one
has recently authenticated.

Note that the BrowserID assertion is generated by an embedded web control
(using WebKit on OS X, and the Internet Explorer Platform API on Windows).

## Building

The following packages are required:

* Jansson <http://www.digip.org/jansson/>
* Kerberos 5 <http://web.mit.edu/kerberos/> or <http://www.h5l.org/>
  (This can be omitted if you are only building libbrowserid.)
* OpenSSL <http://www.openssl.org/> (not required for Windows)
* Curl <http://curl.haxx.se/> (not required for Windows)
* For client-side support, a recent Mac OS X or Windows system. (See end
  of this document for limitations of the Windows port.)

Optional:

* OpenSAML <https://wiki.shibboleth.net/confluence/display/OpenSAML/Home>
* Shibboleth <http://shibboleth.net/>

## Installation

Build similar to the following:

    ./autogen.sh
    build/clang-heimdal-build.sh

You can enable additional debugging with the GSSBID\_DEBUG compile time flag.
This is presently mandatory on OS X to use the client with command-line
utilities (set OBJCFLAGS=-DGSSBID\_DEBUG before running configure).

Edit /usr/local/etc/gss/mech (replace path as appropriate) and add the
following mechanisms, updating the path as appropriate:

    browserid-aes128    1.3.6.1.4.1.5322.24.1.17 /usr/local/lib/gss/mech_browserid.so

## Mutual authentication

There is experimental support for mutual authentication. Create the file
/usr/local/etc/gss/browserid.json (replace path as appropriate) and with
the following keys:

    {
        "private-key": "/usr/local/etc/gss/serverkey.pem",
        "certificate": "/usr/local/etc/gss/certs/servercert.pem",
        "ca-certificate": "/usr/local/etc/gss/certs/cacert.pem"
    }

You can use OpenSSL to create these files as you would when setting a server up
for TLS. The subjectAltName or the CN must match the acceptor host name.

## Other configruation

You can configure the maximum ticket lifetime and renewable lifetime with
the maxticketage and maxrenewage properties in browserid.json, respectively
(this is the same file used to configure mutual authentication above).

Otherwise, the GSS BrowserID mechanism sets the ticket lifetime to 10 hours
and the renewable lifetime to 7 days.

Clock skew is not currently configurable but may be in a future release.

## Testing

### gss-sample

gss-sample can be found in src/appl/gss-sample in the MIT Kerberos
distribution.

    % gss-client -port 5555 -mech "{1 3 6 1 4 1 5322 24 1 17}" localhost host "Testing GSS BrowserID"
    % gss-server -port 5555 -export host

If you are testing between different machines, then you should do (replacing
server as appropriate)

    % gss-client -port 5555 -mech "{1 3 6 1 4 1 5322 24 1 17}" \
      server.browserid.org host@server.browserid.org "Testing GSS BrowserID"
    % gss-server -port 5555 -export host@server.browserid.org

Note that if you test the browserid-none (no key) mechanism than the message
protection tests will fail.

### SASL

SASL samples can be found in the sample directory of the Cyrus SASL
distribution. However, the GS2 mechanism presently needs a patch to support
mechanisms without mutual authentication (this can be found in contrib).

    % export SASL_PATH=/usr/local/lib/sasl2
    % client -C -p 5556 -s host -m BROWSERID-AES128 server.browserid.org
    % server -c -p 5556 -s host -h server.browserid.org

Be sure to set the SASL\_PATH environment variable correctly to point to where
you installed the libgs2.so plugin.

### OpenSSH

Mechanism-agnostic versions of OpenSSH such as those shipped with Moonshot
should work with BrowserID. Unfortunately due to the way OpenSSH works, you
will be prompted twice for credentials. You must have a local account that
matches the BrowserID subject name and be sure to pass that to ssh, as there is
a direct equivalence test.

    % ssh -l lukeh@padl.com -oGSSAPIAuthentication=yes -oGSSAPIKeyExchange=no \
      -oPubkeyAuthentication=no -oPasswordAuthentication=no server.browserid.org
    % sshd -f /etc/sshd\_config -o PubkeyAuthentication=no -o PasswordAuthentication=no

Note that if the server name has aliases (i.e. you can't guarantee which name
the client will choose, you'll also need to set the
GSSAPIStrictAcceptorCheck=no option.

### IMAP

The Cyrus IMAP server works fine with the GSS BrowserID mechanism. Note that
if you haven't configured mutual authentication, you will need to apply the
patch in contrib/cyrus-sasl.patch and rebuild the GS2 plugin.

It's also possible to use the OS X Mail application with GSS BrowserID. You
will need to build a small plugin that allows the mechanism to pose as the
GSSAPI SASL mechanism. See contrib/BrowserIDHelper.

## bidtool

The BrowserID tool, bidtool, is provided for managing ticket, replay and
authority caches.

### Ticket

Normal mode:

    % bidtool tlist 
    Ticket cache: /Users/lukeh/Library/Caches/com.padl.gss.BrowserID/browserid.tickets.json
    
    Identity        Audience                  Issuer        Expires                 
    --------------------------------------------------------------------------------
    lukeh@lukktone. imap/mail.lukktone.com    login.persona Fri Feb  8 04:58:50 2013

Verbose mode:

    % bidtool tlist -verbose
    Ticket cache: /Users/lukeh/Library/Caches/com.padl.gss.BrowserID/browserid.tickets.json

    Audience:         urn:x-gss:imap/mail.lukktone.com
    Subject:          lukeh@lukktone.com
    Issuer:           login.persona.org
    ECDH curve:       P-256
    Cert issue time:  Thu Feb  7 18:58:49 2013
    Cert expiry:      Thu Feb  7 19:58:49 2013
    Ticket expiry:    Fri Feb  8 04:58:50 2013
    Ticket flags:     MUTUAL

### Replay

    % bidtool rlist
    Replay cache:     /Users/lukeh/Library/Caches/com.padl.gss.BrowserID/browserid.replay.json

    Timestamp                 Ticket ID
    ------------------------------------------------------------------------------------------
    Sat Jan  5 15:08:08 2013  D0741E786FCF1A11BBA0609A0EDB20C17A00CE79F4890EE8FF7AF7014EB47781
    Sat Jan  5 15:03:04 2013  0E6817660A9DBAAAD0BB57009005B11AD123B49D29B925BBCFDFDE37CC23B42C
    Thu Jan  3 18:12:33 2013  28A07D0E43887E0CBAEBE371F10F1921AF188ECA131386A660B50AA1F4EF2890
    Thu Jan  3 16:08:43 2013  843BCC577F65EF0AA5E830885C0B67FE215493B397E2EA1BE987A58A2486098B

### Authority 

    % bidtool certlist
    Issuer                         ALG  Expires             
    ------------------------------------------------------------
    login.persona.org              RSA  Tue Jan  8 19:16:29 

## Windows port

The Windows port comes with some fairly significant limitations. First, the
build environment is not included. If you require support for legacy JWK keys
(the answer to which is probably yes), then you will need to link in the
OpenSSL bignum library and compile with -DBID\_DECIMAL\_BIGNUM.

Finally, and this is the greatest usability limitation: there is a bug where
you are only able to acquire an assertion with a fresh cookie/localstorage
state. On subsequent attempts, the Persona login window will hang.

On the positive side, the Windows port uses the platform native web, HTTP and
crypto APIs, so you do not need to link in WebKit, Curl or OpenSSL.
