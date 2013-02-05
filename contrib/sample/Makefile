CFLAGS=-I../.. -I../../libbrowserid
LDFLAGS=-L/usr/local/lib -L../../libbrowserid/.libs
LIBS=-lbrowserid

all: bidget bidverify

bidget: bidget.o
	clang -o $@ $^ $(LDFLAGS) $(LIBS)

bidget.o: bidget.c
	clang $(CFLAGS) -g -Wall -c -o $@ $^

bidverify: bidverify.o
	clang -o $@ $^ $(LDFLAGS) $(LIBS)

bidverify.o: bidverify.c
	clang $(CFLAGS) -g -Wall -c -o $@ $^

clean:
	rm -f bidget bidverify *.o

