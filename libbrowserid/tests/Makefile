all: bid_sig bid_vfy bid_doc bid_acq bid_b32 bid_b64 bid_acq.so bid_acq_ldr bid_fct

bid_sig: bid_sig.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_sig bid_sig.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_vfy: bid_vfy.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_vfy bid_vfy.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_doc: bid_doc.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_doc bid_doc.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_acq: bid_acq.m ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_acq bid_acq.m -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl -framework WebKit -framework AppKit

bid_acq.so: bid_acq.m ../libbrowserid.la
	clang -DBUILD_AS_DSO -I../.. -I.. -g -Wall -bundle -o bid_acq.so bid_acq.m -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl -framework WebKit -framework AppKit

bid_acq_ldr: bid_acq_ldr.c
	clang -I../.. -I.. -g -Wall -o bid_acq_ldr bid_acq_ldr.c
#-Wl,-sectcreate,__TEXT,__info_plist,Info.plist
#-lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_b32: bid_b32.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_b32 bid_b32.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_b64: bid_b64.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_b64 bid_b64.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl

bid_fct: bid_fct.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_fct bid_fct.c -lcrypto -L../.libs -lbrowserid -L/usr/local/lib -ljansson -lcurl -framework WebKit -framework AppKit

clean:
	rm -f bid_sig bid_vfy bid_doc bid_acq bid_b64 bid_acq_ldr bid_acq.so bid_fct

