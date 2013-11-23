# bidtool

The BrowserID tool, bidtool, is provided for managing ticket, replay and
authority caches.

## Ticket

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

## Replay

    % bidtool rlist
    Replay cache:     /Users/lukeh/Library/Caches/com.padl.gss.BrowserID/browserid.replay.json

    Timestamp                 Ticket ID
    ------------------------------------------------------------------------------------------
    Sat Jan  5 15:08:08 2013  D0741E786FCF1A11BBA0609A0EDB20C17A00CE79F4890EE8FF7AF7014EB47781
    Sat Jan  5 15:03:04 2013  0E6817660A9DBAAAD0BB57009005B11AD123B49D29B925BBCFDFDE37CC23B42C
    Thu Jan  3 18:12:33 2013  28A07D0E43887E0CBAEBE371F10F1921AF188ECA131386A660B50AA1F4EF2890
    Thu Jan  3 16:08:43 2013  843BCC577F65EF0AA5E830885C0B67FE215493B397E2EA1BE987A58A2486098B

## Authority 

    % bidtool certlist
    Issuer                         ALG  Expires             
    ------------------------------------------------------------
    login.persona.org              RSA  Tue Jan  8 19:16:29 

