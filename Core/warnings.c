#include "Python.h"

int
PyErr_WarnExplicitObject(
    PyObject *category,
    PyObject *message,
    PyObject *filename,
    int lineno,
    PyObject *module,
    PyObject *registry
) {
    return -1;
}

int
PyErr_WarnExplicit(
    PyObject *category,
    const char *message,
    const char *filename,
    int lineno,
    const char *module,
    PyObject *registry
) {
    return -1;
}

int
PyErr_Warn(
    PyObject *category,
    const char *message
) {
    return PyErr_WarnEx(category, message, 1);
}

int
PyErr_WarnEx(
    PyObject *category,
    const char *message,
    Py_ssize_t stack_level
) {
    return -1;
}

int
PyErr_WarnFormat(
    PyObject *category,
    Py_ssize_t stack_level,
    const char *format,
    ...
) {
    return -1;
}
