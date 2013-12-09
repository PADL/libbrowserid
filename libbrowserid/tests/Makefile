LIBS=-framework CoreFoundation -framework Foundation
CFLAGS=-ObjC -I../.. -I.. -I../../libcfjson -DGSSBID_DEBUG -g -Wall

# most of these tests will require libbrowserid to be built as a static library

all: bid_acq

bid_sig: bid_sig.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_sig bid_sig.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_vfy: bid_vfy.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_vfy bid_vfy.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_doc: bid_doc.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_doc bid_doc.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_acq: bid_acq.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_acq bid_acq.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

bid_cf: bid_cf.m ../libbrowserid.la
	clang $(CFLAGS) -o bid_cf bid_cf.m -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

bid_acq.so: bid_acq.c ../libbrowserid.la
	clang -DBUILD_AS_DSO $(CFLAGS) -o bid_acq.so bid_acq.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

bid_acq_ldr: bid_acq_ldr.c
	clang $(CFLAGS) -o bid_acq_ldr bid_acq_ldr.c
#-Wl,-sectcreate,__TEXT,__info_plist,Info.plist
#-lcrypto -L../.libs -lbrowserid $(LIBS)

bid_b64: bid_b64.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_b64 bid_b64.c -lcrypto -L../.libs -lbrowserid $(LIBS)

bid_fct: bid_fct.c ../libbrowserid.la
	clang $(CFLAGS) -o bid_fct bid_fct.c -lcrypto -L../.libs -lbrowserid $(LIBS) -framework WebKit -framework AppKit

clean:
	rm -f bid_sig bid_vfy bid_doc bid_acq bid_b64 bid_acq_ldr bid_acq.so bid_fct

