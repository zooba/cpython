/* Module definition and import interface */

#ifndef Py_IMPORT_H
#define Py_IMPORT_H
#ifdef __cplusplus
extern "C" {
#endif

PyAPI_FUNC(PyObject *) PyImport_GetModuleDict(void);
PyAPI_FUNC(PyObject *) PyImport_GetModule(const char *name);
PyAPI_FUNC(PyObject *) PyImport_GetModuleObject(PyObject *name);
PyAPI_FUNC(PyObject *) PyImport_SetModule(const char *name, PyObject *module);
PyAPI_FUNC(PyObject *) PyImport_SetModuleObject(PyObject *name, PyObject *module);

PyAPI_FUNC(PyObject *) PyImport_NewModule(const char *name);

PyAPI_FUNC(PyObject *) PyImport_ImportModule(const char *name);
PyAPI_FUNC(PyObject *) PyImport_ImportModuleNoBlock(const char *name);
PyAPI_FUNC(PyObject *) PyImport_Import(PyObject *name);
PyAPI_FUNC(PyObject *) PyImport_ReloadModule(PyObject *m);

PyAPI_FUNC(void) _PyImport_AcquireLock(void);
PyAPI_FUNC(int) _PyImport_ReleaseLock(void);
PyAPI_FUNC(void) _PyImport_ReInitLock(void);

#ifdef __cplusplus
}
#endif
#endif /* !Py_IMPORT_H */
