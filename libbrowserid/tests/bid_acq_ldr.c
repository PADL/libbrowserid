#include <stdlib.h>
#include <dlfcn.h>

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

