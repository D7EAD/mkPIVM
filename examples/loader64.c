#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <blob.bin>\n", argv[0]);
        return 2;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* p = VirtualAlloc(NULL, (SIZE_T)n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        fclose(f);
        return 2;
    }

    if (fread(p, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "fread failed\n");
        fclose(f);
        return 2;
    }
    
    fclose(f);

    DWORD old;
    if (!VirtualProtect(p, (SIZE_T)n, PAGE_EXECUTE_READ, &old)) {
        fprintf(stderr, "VirtualProtect to RX failed: %lu\n", GetLastError());
        return 2;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC vp = GetProcAddress(k32, "VirtualProtect");
    if (!vp) {
        fprintf(stderr, "GetProcAddress(VirtualProtect) failed\n");
        return 2;
    }

    ((void (*)(void*))p)((void*)vp);

    return 0;
}
