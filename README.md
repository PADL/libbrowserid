# libbrowserid

libbrowserid is a C library for generating and verifying Mozilla Persona
(BrowserID) assertions. This source distribution also includes a GSS/SASL
mechanism based on the BrowserID protocol, but that is not built by default.

More information on BrowserID is available at the URL
<https://developer.mozilla.org/en-US/docs/persona>.

## Building

The following packages are required:

* Jansson <http://www.digip.org/jansson/>
* Curl <http://curl.haxx.se/> (not required for Windows or OS X)
* OpenSSL <http://www.openssl.org/> (not required for Windows)

Building is similar to other autotools-based projects; run ./autogen.sh,
./configure and make. If you wish to also build the GSS/SASL mechanism, see the
instructions in mech\_browserid/README.md.

## Sample code

Sample code can be found in the sample directory. See doc/sample.md for more
information.

