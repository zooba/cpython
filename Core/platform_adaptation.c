#define PY_SSIZE_T_CLEAN
#include "Python.h"

// TODO: Implement initialization

void Py_FatalError(const char *message)
{
    exit(0);
}

void Py_DebugOutput(const char *message)
{
}

long PyErr_NativeCodeToErrno(size_t error)
{
    return (long)error;
}
