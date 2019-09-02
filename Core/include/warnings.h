#ifndef Py_WARNINGS_H
#define Py_WARNINGS_H
#ifdef __cplusplus
extern "C" {
#endif

PyAPI_FUNC(int) PyErr_Warn(PyObject *category, const char *message);
PyAPI_FUNC(int) PyErr_WarnEx(PyObject *category, const char *message, Py_ssize_t stack_level);
PyAPI_FUNC(int) PyErr_WarnFormat(
    PyObject *category,
    Py_ssize_t stack_level,
    const char *format,         /* ASCII-encoded string  */
    ...);

PyAPI_FUNC(int) PyErr_WarnExplicitObject(
    PyObject *category,
    PyObject *message,
    PyObject *filename,
    int lineno,
    PyObject *module,
    PyObject *registry);
PyAPI_FUNC(int) PyErr_WarnExplicit(
    PyObject *category,
    const char *message,
    const char *filename,
    int lineno,
    const char *module,
    PyObject *registry);

#ifdef __cplusplus
}
#endif
#endif /* !Py_WARNINGS_H */

