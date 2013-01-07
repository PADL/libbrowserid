# BrowserID GSS Mechanism

The BrowserID GSS mechanism is a plugin for the GSS-API that allows you to use
BrowserID-generated assertions for signing in to non-web protocols, such as
SMTP, IMAP, SSH, LDAP, CIFS, and NFS. Any protocol that supports GSS-API or
SASL and does not require mutual authentication should work.

More information on BrowserID is available at the URL
<https://developer.mozilla.org/en-US/docs/persona>.

## Building

The following packages are required:

* Jansson <http://www.digip.org/jansson/>
* OpenSSL <http://www.openssl.org/>
* Kerberos 5 <http://web.mit.edu/kerberos/> or <http://www.h5l.org/>
* Curl <http://curl.haxx.se/>
* Currently, a recent Mac OS X system, as the embedded browser only supports WebKit

Optional:

* OpenSAML <https://wiki.shibboleth.net/confluence/display/OpenSAML/Home>
* Shibboleth <http://shibboleth.net/>

## Installation

Build similar to the following:

    ./autogen.sh
    OBJC=clang CC=clang CXX=clang++ ./configure

You can enable additional debugging with the GSSBID\_DEBUG compile time flag.
This is presently mandatory on OS X to use the client with command-line
utilities (set OBJCFLAGS=-DGSSBID\_DEBUG before running configure).

Edit /usr/local/etc/gss/mech (replace path as appropriate) and add the
following mechanisms, updating the path as appropriate:

    browserid-aes128    1.3.6.1.4.1.5322.24.1.17 /usr/local/lib/gss/mech_browserid.so

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

