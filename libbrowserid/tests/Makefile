all: bid_sig bid_vfy bid_doc bid_acq bid_b64

bid_sig: bid_sig.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_sig bid_sig.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_vfy: bid_vfy.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_vfy bid_vfy.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_doc: bid_doc.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_doc bid_doc.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_acq: bid_acq.m ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_acq bid_acq.m -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl -framework WebKit -framework AppKit

bid_b64: bid_b64.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_b64 bid_b64.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl -framework WebKit -framework AppKit

clean:
	rm -f bid_sig bid_vfy bid_doc bid_acq bid_b64

