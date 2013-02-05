LIBS=-L/usr/local/lib -ljansson -lcurl

# most of these tests will require libbrowserid to be built as a static library

all: bid_acq

bid_sig: bid_sig.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_sig bid_sig.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_vfy: bid_vfy.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_vfy bid_vfy.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_doc: bid_doc.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_doc bid_doc.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_acq: bid_acq.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_acq bid_acq.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

bid_acq.so: bid_acq.c ../libbrowserid.la
	clang -DBUILD_AS_DSO -I../.. -I.. -g -Wall -bundle -o bid_acq.so bid_acq.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

bid_acq_ldr: bid_acq_ldr.c
	clang -I../.. -I.. -g -Wall -o bid_acq_ldr bid_acq_ldr.c
#-Wl,-sectcreate,__TEXT,__info_plist,Info.plist
#-lcrypto -L../.libs -lbrowserid $(LIBS)

bid_b64: bid_b64.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_b64 bid_b64.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_fct: bid_fct.c ../libbrowserid.la
	clang -I../.. -I.. -g -Wall -o bid_fct bid_fct.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

clean:
	rm -f bid_sig bid_vfy bid_doc bid_acq bid_b64 bid_acq_ldr bid_acq.so bid_fct

