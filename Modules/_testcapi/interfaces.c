#define PYTESTCAPI_NEED_INTERNAL_API

#include "parts.h"
#include "util.h"


static PyObject *
interface_getattrwchar(PyObject *Py_UNUSED(module), PyObject *args)
{
    PyObject *obj = NULL;
    PyObject *attro = NULL;
    if (!PyArg_ParseTuple(args, "OO", &obj, &attro)) {
        return NULL;
    }
    wchar_t *attr = PyUnicode_AsWideCharString(attro, NULL);
    if (!attr) {
        return NULL;
    }

    Py_INTERFACE_VAR(PyInterface_GetAttrWChar, attr_data);
    if (PyObject_GetInterface(obj, &attr_data) < 0) {
        PyMem_Free(attr);
        return NULL;
    }
    PyObject *result = Py_INTERFACE_CALL(attr_data, getattr, attr);
    PyInterface_Release(&attr_data);
    PyMem_Free(attr);
    return result;
}


static PyMethodDef test_methods[] = {
    {"interface_getattrwchar", interface_getattrwchar, METH_VARARGS},
    {NULL},
};


int
_PyTestCapi_Init_Interfaces(PyObject *m)
{
    return PyModule_AddFunctions(m, test_methods);
}
