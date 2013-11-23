# libbrowserid sample code

The sample directory contains some example code.

## bidget

bidget displays UI to acquire an assertion for a given audience. The assertion
is printed to the standard output. Note that this will only work on OS X and
Windows at present, as only those platforms have UI support in libbrowserid.

## bidverify

bidverify verifies an assertion for a given audience. It takes the audience and
assertion as command line outputs. The expiry time, subject and issuer are
printed on the standard output.

## bidcfget

bidcfget is a variant of bidget implemented using the CoreFoundation BrowserID
API.

## bidcfverify

bidcfverify is a variant of bidverify implemented using the CoreFoundation
BrowserID API.

