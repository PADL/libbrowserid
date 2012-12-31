/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdlib.h>
#include <dlfcn.h>

/*
 * Test using libbrowserid from a shared object.
 */
int main(int argc, char *argv[])
{
    int (*sym)(void);
    void *dl;

    dl = dlopen("./bid_acq.so", RTLD_LOCAL);
    if (dl != NULL) {
        sym = dlsym(dl, "_BIDTestAcquire");
        if (sym != NULL) {
            sym();
        }
        dlclose(dl);
    }

    exit(0);
}

