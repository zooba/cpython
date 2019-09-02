#define PY_SSIZE_T_CLEAN
#include "Python.h"

PyObject *
PyImport_GetModuleDict(void)
{
    return NULL;
}

PyObject *
PyImport_GetModule(const char *name)
{
    return NULL;
}

PyObject *
PyImport_GetModuleObject(PyObject *name)
{
    return NULL;
}

PyObject *
PyImport_SetModule(const char *name, PyObject *module)
{
    return NULL;
}

PyObject *
PyImport_SetModuleObject(PyObject *name, PyObject *module)
{
    return NULL;
}

PyObject *
PyImport_NewModule(const char *name)
{
    return NULL;
}

PyObject *
PyImport_ImportModule(const char *name)
{
    return NULL;
}

PyObject *
PyImport_ImportObject(PyObject *name)
{
    return NULL;
}

PyObject *
PyImport_ReloadModule(PyObject *m)
{
    return NULL;
}

PyObject *
PyImport_ImportModuleNoBlock(const char *name)
{
    return NULL;
}

void
_PyImport_AcquireLock(void)
{
}

int
_PyImport_ReleaseLock(void)
{
    return -1;
}

void
_PyImport_ReInitLock(void)
{
}
