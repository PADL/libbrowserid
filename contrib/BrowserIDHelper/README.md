### Using BrowserID with OS X Mail

Not for the faint of heart. You will need an IMAP server that supports
BrowserID: I have tested with Cyrus SASL.

* Build and install the Mail.app plugin in this directory
* Copy or symlink Cyrus SASL's libgs2.so AND libgs2.la into /usr/lib/sasl2
* Apply the sandbox patch in application.sb.diff, adjusting paths as necessary
* rm -f ~/Library/Containers/com.apple.mail/Container.plist
* Start Mail.app
* In Preferences/Accounts/Advanced for your mail server, set Authentication to
  "Kerberos Version 5 (GSSAPI)" (as that is what BrowserID will masquerade as
  to Mail.app)
* Enjoy

