#define PY_SSIZE_T_CLEAN
#include "Python.h"

void *
PyMem_Malloc(size_t bytes)
{
    return malloc(bytes);
}

void *
PyMem_Realloc(void *mem, size_t bytes)
{
    return realloc(mem, bytes);
}

void
PyMem_Free(void *mem)
{
    free(mem);
}

void *
PyMem_RawMalloc(size_t bytes)
{
    return malloc(bytes);
}

void *
PyMem_RawRealloc(void *mem, size_t bytes)
{
    return realloc(mem, bytes);
}

void
PyMem_RawFree(void *mem)
{
    free(mem);
}

void *
PyObject_Malloc(size_t bytes)
{
    void *b = malloc(bytes);
    if (!b) {
        // TODO: Set error
        return b;
    }
    memset(b, 0, bytes);
    return b;
}

void *
PyObject_Realloc(void *mem, size_t bytes)
{
    return realloc(mem, bytes);
}


void
PyObject_Free(void *mem)
{
    free(mem);
}

char *
_PyMem_Strdup(const char* s)
{
    size_t len = strlen(s) + 1;
    char *s2 = (char *)malloc(len);
    strcpy_s(s2, len, s);
    return s2;
}