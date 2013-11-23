# libbrowserid

libbrowserid is a C library for generating and verifying Mozilla Persona
(BrowserID) assertions. This source distribution also includes a GSS/SASL
mechanism based on the BrowserID protocol, but that is not built by default.

More information on BrowserID is available at the URL
<https://developer.mozilla.org/en-US/docs/persona>.

## Building

The following packages are required:

* Jansson <http://www.digip.org/jansson/>
* Curl <http://curl.haxx.se/> (not required for Windows)
* OpenSSL <http://www.openssl.org/> (not required for Windows)

Building is similar to other autotools-based projects; run ./autogen.sh,
./configure and make. If you wish to also build the GSS/SASL mechanism, see the
instructions in mech\_browserid/README.md.

## Sample code

Sample code can be found in the sample directory. See sample/README.md for more
information.

## CoreFoundation support

If you have the CoreFoundation internal headers installed (CFRuntime.h), then
you can build libbrowserid such that it exposes its types as first-class
CoreFoundation objects. You can also use the helper APIs in CFBrowserID.h.

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
