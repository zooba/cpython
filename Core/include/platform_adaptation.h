
/* Platform adaptation layer */

#ifndef Py_PLATFORM_ADAPTATION_H
#define Py_PLATFORM_ADAPTATION_H
#ifdef __cplusplus
extern "C" {
#endif

PyAPI_FUNC(long) PyErr_NativeCodeToErrno(size_t error);

#ifdef __cplusplus
}
#endif
#endif /* !Py_PLATFORM_ADAPTATION_H */
