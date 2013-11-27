# iOS support

There is some support for UIKit/WebKit. However it has some limitations: it
runs its own event loop to present a modal view, which is not really
iOS-friendly, and currently it only builds from the command line, so you will
need to use a script such as the one in build/clang-ios-build.sh to
cross-compile.

