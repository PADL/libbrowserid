#!/bin/sh
OBJC=clang CC=clang CXX=clang++ OBJCFLAGS="-g -Wall -DGSSBID_DEBUG -Wno-deprecated-declarations" CXXFLAGS="-g -Wall -DGSSBID_DEBUG -Wno-deprecated-declarations" CFLAGS="-g -Wall -DGSSBID_DEBUG -Wno-deprecated-declarations" ./configure --with-krb5=/usr/local/heimdal --with-opensaml=no --with-shibresolver=no --with-shibsp=no
