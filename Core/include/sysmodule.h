
/* System module interface */

#ifndef Py_SYSMODULE_H
#define Py_SYSMODULE_H
#ifdef __cplusplus
extern "C" {
#endif

PyAPI_FUNC(PyObject *) PySys_GetObject(const char *);
PyAPI_FUNC(int) PySys_SetObject(const char *, PyObject *);

PyAPI_FUNC(void) PySys_WriteStdout(const char *format, ...);
PyAPI_FUNC(void) PySys_WriteStderr(const char *format, ...);

PyAPI_FUNC(size_t) _PySys_GetSizeOf(PyObject *);

typedef int(*Py_AuditHookFunction)(const char *, PyObject *, void *);

PyAPI_FUNC(int) PySys_Audit(const char*, const char *, ...);
PyAPI_FUNC(int) PySys_AddAuditHook(Py_AuditHookFunction, void*);

#ifdef __cplusplus
}
#endif
#endif /* !Py_SYSMODULE_H */
