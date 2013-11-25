#!/bin/bash
export OBJC=clang
export CC=clang
export CXX=clang++
 export XCODE_BASE=/Applications/Xcode.app/Contents
export SIMULATOR_BASE=$XCODE_BASE/Developer/Platforms/iPhoneSimulator.platform
export FRAMEWORKS=$SIMULATOR_BASE/Developer/SDKs/iPhoneSimulator7.0.sdk/System/Library/Frameworks
export INCLUDES=$SIMULATOR_BASE/Developer/SDKs/iPhoneSimulator7.0.sdk/usr/include
export CFLAGS="-I/usr/local/ios/include -I/Users/lukeh/CVSRoot/OpenSSL-for-iPhone/include -I$INCLUDES -F$FRAMEWORKS -g -Wall -DGSSBID_DEBUG -Wno-deprecated-declarations -mios-simulator-version-min=7.0 -fobjc-abi-version=2 -isysroot $SIMULATOR_BASE/Developer/SDKs/iPhoneSimulator7.0.sdk"
export LIBS="-L/usr/local/ios/lib"
export LDFLAGS="-syslibroot$SIMULATOR_BASE/Developer/SDKs/iPhoneSimulator7.0.sdk"
export OBJCFLAGS="$CFLAGS"
export CXXFLAGS="$CFLAGS"
export target_ios=yes
#export LIBS="-lssl -lcrypto"

./configure --with-jansson=/usr/local/ios --with-opensaml=none --with-shibresolver=none --with-shibsp=none --enable-gss-mech=no --with-openssl=/usr/local/ios --prefix=/usr/local/ios

