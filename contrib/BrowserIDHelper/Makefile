BrowserIDHelper: BrowserIDHelper.o
	clang -bundle -o $@ $^ -framework Foundation -F/System/Library/PrivateFrameworks

BrowserIDHelper.o: BrowserIDHelper.m
	clang -g -Wall -c -o $@ $^

clean:
	rm -f BrowserIDHelper BrowserIDHelper.o

install:
	rm -f ~/Library/Containers/com.apple.mail/Container.plist
	mkdir -p ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents/MacOS
	cp BrowserIDHelper ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents/MacOS
	cp Info.plist ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle/Contents

uninstall:
	rm -rf ~/Library/Mail/Bundles/BrowserIDHelper.mailbundle



