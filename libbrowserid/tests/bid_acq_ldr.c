#include <stdlib.h>
#include <dlfcn.h>
#include <ApplicationServices/ApplicationServices.h>

int main(int argc, char *argv[])
{
    int (*sym)(void);
    void *dl;

#ifdef __APPLE__
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToUIElementApplication);
#endif

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

