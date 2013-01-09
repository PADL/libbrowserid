BrowserIDHelper: BrowserIDHelper.o
	clang -bundle -o $@ $^ -framework Foundation -F/System/Library/PrivateFrameworks -framework CoreMessage -framework IMAP -lSystem -lsasl2

BrowserIDHelper.o: BrowserIDHelper.m
	clang -g -Wall -c -o $@ $^

clean:
	rm -f BrowserIDHelper BrowserIDHelper.o

install:
	mkdir -p ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents/MacOS
	cp BrowserIDHelper ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents/MacOS
	cp Info.plist ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents
