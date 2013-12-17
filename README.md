[![Build Status](https://travis-ci.org/PADL/libbrowserid.png?branch=browserid)](https://travis-ci.org/PADL/libbrowserid)

# libbrowserid

libbrowserid is a C library for generating and verifying Mozilla Persona
(BrowserID) assertions. This source distribution also includes a GSS/SASL
mechanism based on the BrowserID protocol, but that is not built by default.

More information on BrowserID is available at the URL
<https://developer.mozilla.org/en-US/docs/persona>.

## Building

For building on Mac OS X, no additional packages are required.

On Windows you will additionally need:

* Jansson <http://www.digip.org/jansson/>

On all other platforms, you will need, in addition to Jansson:

* Curl <http://curl.haxx.se/> (not required for Windows)
* OpenSSL <http://www.openssl.org/> (not required for Windows)

Building is similar to other autotools-based projects; run ./autogen.sh,
./configure and make. If you wish to also build the GSS/SASL mechanism, see the
instructions in mech\_browserid/README.md.

## Sample code

Sample code can be found in the sample directory. See doc/sample.md for more
information.

