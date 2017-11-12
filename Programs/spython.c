/* Minimal main program -- everything is loaded from the library */

#include "Python.h"
#include "opcode.h"
#include <locale.h>
#include <string.h>

#ifdef __FreeBSD__
#include <fenv.h>
#endif

#ifdef MS_WINDOWS
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#endif

#define HOOK_CLEARAUDITHOOKS
#define HOOK_ADDAUDITHOOK
#define HOOK_OPEN_FOR_IMPORT
#define HOOK_IMPORT
#define HOOK_COMPILE
#define HOOK_CODE_NEW
#define HOOK_EXEC
#define HOOK_ID
#define HOOK_SETATTR
#define HOOK_DELATTR
#define HOOK_PICKLE_FIND_CLASS
#define HOOK_SYSTEM

#ifdef HOOK_CLEARAUDITHOOKS
static int
hook_clearaudithooks(const char *event, PyObject *args, FILE *audit_log)
{
    fprintf(audit_log, "%s: closing log\n", event);
    if (audit_log != stderr)
        fclose(audit_log);
    audit_log = NULL;
    return 0;
}
#endif

#ifdef HOOK_ADDAUDITHOOK
static int
hook_addaudithook(const char *event, PyObject *args, FILE *audit_log)
{
    fprintf(audit_log, "%s: hook was not added\n", event);
    PyErr_SetString(PyExc_SystemError, "hook not permitted");
    return -1;
}
#endif

#ifdef HOOK_OPEN_FOR_IMPORT
// Note that this event is raised by our hook below - it is not a "standard" audit item
static int
hook_open_for_import(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *path = PyTuple_GetItem(args, 0);
    PyObject *disallow = PyTuple_GetItem(args, 1);

    PyObject *msg = PyUnicode_FromFormat("'%S'; allowed = %S", path, disallow);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);

    return 0;
}
#endif

#ifdef HOOK_IMPORT
static int
hook_import(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *module, *filename, *sysPath, *sysMetaPath, *sysPathHooks;
    if (!PyArg_ParseTuple(args, "OOOOO",
        &module, &filename, &sysPath, &sysMetaPath, &sysPathHooks))
        return -1;

    PyObject *msg;
    if (PyObject_IsTrue(filename)) {
        msg = PyUnicode_FromFormat("importing %S from %S",
            module, filename);
    } else {
        msg = PyUnicode_FromFormat("importing %S:\n"
            "    sys.path=%S\n"
            "    sys.meta_path=%S\n"
            "    sys.path_hooks=%S",
            module, sysPath, sysMetaPath, sysPathHooks);
    }

    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);

    return 0;
}
#endif

#ifdef HOOK_COMPILE
static int
hook_compile(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *code, *filename, *_;
    if (!PyArg_ParseTuple(args, "OO", &code, &filename,
        &_, &_, &_, &_, &_, &_))
        return -1;

    if (!PyUnicode_Check(code)) {
        code = PyObject_Repr(code);
        if (!code)
            return -1;
    } else {
        Py_INCREF(code);
    }

    if (PyUnicode_GetLength(code) > 200) {
        Py_SETREF(code, PyUnicode_Substring(code, 0, 200));
        if (!code)
            return -1;
        Py_SETREF(code, PyUnicode_FromFormat("%S...", code));
        if (!code)
            return -1;
    }

    PyObject *msg;
    if (PyObject_IsTrue(filename)) {
        if (code == Py_None) {
            msg = PyUnicode_FromFormat("compiling from file %S", filename);
        } else {
            msg = PyUnicode_FromFormat("compiling %S: %S", filename, code);
        }
    } else {
        msg = PyUnicode_FromFormat("compiling: %R", code);
    }
    Py_DECREF(code);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    return 0;
}
#endif

#ifdef HOOK_CODE_NEW
static int
hook_code_new(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *code, *filename, *name;
    int argcount, kwonlyargcount, nlocals, stacksize, flags;
    if (!PyArg_ParseTuple(args, "OOOiiiii", &code, &filename, &name,
        &argcount, &kwonlyargcount, &nlocals, &stacksize, &flags))
        return -1;

    PyObject *msg = PyUnicode_FromFormat("compiling: %R", filename);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);

    if (!PyBytes_Check(code)) {
        PyErr_SetString(PyExc_TypeError, "Invalid bytecode object");
        return -1;
    }

    // As an example, let's validate that no STORE_FAST operations are
    // going to overflow nlocals.
    char *wcode;
    Py_ssize_t wlen;
    if (PyBytes_AsStringAndSize(code, &wcode, &wlen) < 0)
        return -1;

    for (Py_ssize_t i = 0; i < wlen; i += 2) {
        if (wcode[i] == STORE_FAST) {
            if (wcode[i + 1] > nlocals) {
                PyErr_SetString(PyExc_ValueError, "invalid code object");
                fprintf(audit_log, "%s: code stores to local %d but only allocates %d\n", event,
                    wcode[i + 1], nlocals);
                return -1;
            }
        }
    }

    return 0;
}
#endif

#ifdef HOOK_EXEC
static int
hook_exec(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *codeObj;
    if (!PyArg_ParseTuple(args, "O", &codeObj))
        return -1;

    PyObject *msg = PyUnicode_FromFormat("%R", codeObj);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    return 0;
}
#endif

#ifdef HOOK_ID
static int
hook_id(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *id = PyTuple_GetItem(args, 0);

    PyObject *msg = _PyLong_Format(id, 16);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    return 0;
}
#endif

#ifdef HOOK_SETATTR
static int
hook_setattr(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *obj, *attr, *value;
    if (!PyArg_ParseTuple(args, "OOO", &obj, &attr, &value))
        return -1;

    /* Cannot render message during initialization */
    if (!Py_IsInitialized())
        return 0;

    PyObject *msg = PyUnicode_FromFormat("setattr(%R, \"%S\", %R instance at %p)",
        obj, attr, Py_TYPE(value), value);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    return 0;
}
#endif

#ifdef HOOK_DELATTR
static int
hook_delattr(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *obj, *attr;
    if (!PyArg_ParseTuple(args, "OO", &obj, &attr))
        return -1;

    /* Cannot render message during initialization */
    if (!Py_IsInitialized())
        return 0;

    PyObject *msg = PyUnicode_FromFormat("delattr(%R, \"%S\")", obj, attr);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    return 0;
}
#endif

#ifdef HOOK_PICKLE_FIND_CLASS
static int
hook_pickle_find_class(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *mod = PyTuple_GetItem(args, 0);
    PyObject *global = PyTuple_GetItem(args, 1);

    PyObject *msg = PyUnicode_FromFormat("finding %R.%R blocked",
        mod, global);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);
    PyErr_SetString(PyExc_RuntimeError,
        "unpickling arbitrary objects is disallowed");
    return -1;
}
#endif

#ifdef HOOK_SYSTEM
static int
hook_system(const char *event, PyObject *args, FILE *audit_log)
{
    PyObject *cmd = PyTuple_GetItem(args, 0);

    PyObject *msg = PyUnicode_FromFormat("%S", cmd);
    if (!msg)
        return -1;

    fprintf(audit_log, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);

    PyErr_SetString(PyExc_RuntimeError, "os.system() is disallowed");
    return -1;

    //return 0;
}
#endif

static int
default_spython_hook(const char *event, PyObject *args, void *userData)
{
    assert(userData);

#ifdef HOOK_CLEARAUDITHOOKS
    if (strcmp(event, "sys._clearaudithooks") == 0)
        return hook_clearaudithooks(event, args, (FILE*)userData);
#endif

#ifdef HOOK_ADDAUDITHOOK
    if (strcmp(event, "sys.addaudithook") == 0)
        return hook_addaudithook(event, args, (FILE*)userData);
#endif

#ifdef HOOK_OPEN_FOR_IMPORT
    if (strcmp(event, "spython.open_for_import") == 0)
        return hook_open_for_import(event, args, (FILE*)userData);
#endif

#ifdef HOOK_IMPORT
    if (strcmp(event, "import") == 0)
        return hook_import(event, args, (FILE*)userData);
#endif

#ifdef HOOK_COMPILE
    if (strcmp(event, "compile") == 0)
        return hook_compile(event, args, (FILE*)userData);
#endif

#ifdef HOOK_CODE_NEW
    if (strcmp(event, "code.__new__") == 0)
        return hook_code_new(event, args, (FILE*)userData);
#endif

#ifdef HOOK_EXEC
    if (strcmp(event, "exec") == 0)
        return hook_exec(event, args, (FILE*)userData);
#endif

#ifdef HOOK_ID
    if (strcmp(event, "id") == 0)
        return hook_id(event, args, (FILE*)userData);
#endif

#ifdef HOOK_SETATTR
    if (strcmp(event, "object.__setattr__") == 0)
        return hook_setattr(event, args, (FILE*)userData);
#endif

#ifdef HOOK_DELATTR
    if (strcmp(event, "object.__delattr__") == 0)
        return hook_delattr(event, args, (FILE*)userData);
#endif

#ifdef HOOK_PICKLE_FIND_CLASS
    if (strcmp(event, "pickle.find_class") == 0)
        return hook_pickle_find_class(event, args, (FILE*)userData);
#endif

#ifdef HOOK_SYSTEM
    if (strcmp(event, "system") == 0)
        return hook_system(event, args, (FILE*)userData);
#endif

    // Unknown events just get printed
    PyObject *msg = PyObject_Repr(args);
    if (!msg)
        return -1;

    fprintf((FILE*)userData, "%s: %s\n", event, PyUnicode_AsUTF8(msg));
    Py_DECREF(msg);

    return 0;
}

static PyObject *
spython_open_for_import(PyObject *path)
{
    static PyObject *io = NULL;
    PyObject *stream = NULL;

    const char *ext = strrchr(PyUnicode_AsUTF8(path), '.');
    int disallow = !ext || strcmpi(ext, ".py") != 0;

    PyObject *b = PyBool_FromLong(!disallow);
    if (PySys_Audit("spython.open_for_import", "OO", path, b) < 0) {
        Py_DECREF(b);
        return NULL;
    }
    Py_DECREF(b);

    if (disallow) {
        PyErr_SetString(PyExc_OSError, "invalid format");
        return NULL;
    }

    if (!io) {
        io = PyImport_ImportModule("_io");
        if (!io)
            return NULL;
    }

#ifdef MS_WINDOWS
    /* On Windows, we explicitly open the file without sharing */
    wchar_t *wide = PyUnicode_AsWideCharString(path, NULL);
    if (!wide)
        return NULL;
    SECURITY_ATTRIBUTES secAttrib = { 0 };
    HANDLE hFile = CreateFileW(wide, GENERIC_READ, 0, &secAttrib, OPEN_EXISTING, 0, NULL);
    int err = GetLastError();

    PyMem_Free(wide);
    if (hFile == INVALID_HANDLE_VALUE) {
        PyErr_SetExcFromWindowsErr(PyExc_OSError, err);
        return NULL;
    }

    int fd = _open_osfhandle((intptr_t)hFile, _O_RDONLY);
    if (fd < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        CloseHandle(hFile);
        return NULL;
    }

    stream = PyObject_CallMethod(io, "open", "isisssi", fd, "rb",
        -1, NULL, NULL,
        NULL, 1);
#else
    stream = PyObject_CallMethod(io, "open", "Osisssi", path, "rb",
        -1, NULL, NULL,
        NULL, 1);
#endif

    return stream;
}

static int
spython_usage(int exitcode, wchar_t *program)
{
    FILE *f = exitcode ? stderr : stdout;

    fprintf(f, "usage: %ls file [arg] ...\n" , program);

    return exitcode;
}

static int
spython_main(int argc, wchar_t **argv, FILE *audit_log)
{
    if (argc == 1) {
        return spython_usage(1, argv[0]);
    }

    /* The auditing log should be opened by the platform-specific main */
    if (!audit_log) {
        Py_FatalError("failed to open log file");
        return 1;
    }

#ifdef Py_DEBUG
    if (wcscmp(argv[1], L"-i") == 0) {
        fclose(audit_log);
        audit_log = stderr;
    }
#endif

    PySys_AddAuditHook(default_spython_hook, audit_log);
    PyImport_SetOpenForImportHook(spython_open_for_import);

    Py_IgnoreEnvironmentFlag = 1;
    Py_NoSiteFlag = 1;
    Py_NoUserSiteDirectory = 1;
    Py_DontWriteBytecodeFlag = 1;

    Py_SetProgramName(argv[0]);
    Py_Initialize();
    PySys_SetArgv(argc - 1, &argv[1]);

#ifdef Py_DEBUG
    if (wcscmp(argv[1], L"-i") == 0) {
        PyRun_InteractiveLoop(stdin, "<stdin>");
        Py_Finalize();
        return 0;
    }
#endif

    FILE *fp = _Py_wfopen(argv[1], L"r");
    if (fp != NULL) {
        (void)PyRun_SimpleFile(fp, "__main__");
        PyErr_Clear();
        fclose(fp);
    } else {
        fprintf(stderr, "failed to open source file %ls\n", argv[1]);
    }

    Py_Finalize();
    return 0;
}

#ifdef MS_WINDOWS
int
wmain(int argc, wchar_t **argv)
{
    FILE *audit_log;
    wchar_t *log_path = NULL;
    size_t log_path_len;

    if (_wgetenv_s(&log_path_len, NULL, 0, L"SPYTHONLOG") == 0 && log_path_len) {
        log_path_len += 1;
        log_path = (wchar_t*)malloc(log_path_len * sizeof(wchar_t));
        _wgetenv_s(&log_path_len, log_path, log_path_len, L"SPYTHONLOG");
    } else {
        log_path_len = wcslen(argv[0]) + 5;
        log_path = (wchar_t*)malloc(log_path_len * sizeof(wchar_t));
        wcscpy_s(log_path, log_path_len, argv[0]);
        wcscat_s(log_path, log_path_len, L".log");
    }

    if (_wfopen_s(&audit_log, log_path, L"w")) {
        fwprintf_s(stderr, L"Fatal Python error: "
            L"failed to open log file: %s\n", log_path);
        return 1;
    }
    free(log_path);

    return spython_main(argc, argv, audit_log);
}

#else

/* Access private pylifecycle helper API to better handle the legacy C locale
 *
 * The legacy C locale assumes ASCII as the default text encoding, which
 * causes problems not only for the CPython runtime, but also other
 * components like GNU readline.
 *
 * Accordingly, when the CLI detects it, it attempts to coerce it to a
 * more capable UTF-8 based alternative.
 *
 * See the documentation of the PYTHONCOERCECLOCALE setting for more details.
 *
 */
extern int _Py_LegacyLocaleDetected(void);
extern void _Py_CoerceLegacyLocale(void);

int
main(int argc, char **argv)
{
    wchar_t **argv_copy;
    /* We need a second copy, as Python might modify the first one. */
    wchar_t **argv_copy2;
    int i, res;
    char *oldloc;
    FILE *audit_log;

    /* Force malloc() allocator to bootstrap Python */
#ifdef Py_DEBUG
    (void)_PyMem_SetupAllocators("malloc_debug");
#  else
    (void)_PyMem_SetupAllocators("malloc");
#  endif

    argv_copy = (wchar_t **)PyMem_RawMalloc(sizeof(wchar_t*) * (argc+1));
    argv_copy2 = (wchar_t **)PyMem_RawMalloc(sizeof(wchar_t*) * (argc+1));
    if (!argv_copy || !argv_copy2) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    /* 754 requires that FP exceptions run in "no stop" mode by default,
     * and until C vendors implement C99's ways to control FP exceptions,
     * Python requires non-stop mode.  Alas, some platforms enable FP
     * exceptions by default.  Here we disable them.
     */
#ifdef __FreeBSD__
    fedisableexcept(FE_OVERFLOW);
#endif

    oldloc = _PyMem_RawStrdup(setlocale(LC_ALL, NULL));
    if (!oldloc) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

#ifdef __ANDROID__
    /* Passing "" to setlocale() on Android requests the C locale rather
     * than checking environment variables, so request C.UTF-8 explicitly
     */
    setlocale(LC_ALL, "C.UTF-8");
#else
    /* Reconfigure the locale to the default for this process */
    setlocale(LC_ALL, "");
#endif

    if (_Py_LegacyLocaleDetected()) {
        _Py_CoerceLegacyLocale();
    }

    /* Convert from char to wchar_t based on the locale settings */
    for (i = 0; i < argc; i++) {
        argv_copy[i] = Py_DecodeLocale(argv[i], NULL);
        if (!argv_copy[i]) {
            PyMem_RawFree(oldloc);
            fprintf(stderr, "Fatal Python error: "
                            "unable to decode the command line argument #%i\n",
                            i + 1);
            return 1;
        }
        argv_copy2[i] = argv_copy[i];
    }
    argv_copy2[argc] = argv_copy[argc] = NULL;

    setlocale(LC_ALL, oldloc);
    PyMem_RawFree(oldloc);

    if (getenv("SPYTHONLOG")) {
        audit_log = fopen(getenv("SPYTHONLOG"), "w");
        if (!audit_log) {
            fprintf(stderr, "Fatal Python error: "
                "failed to open log file: %s\n", getenv("SPYTHONLOG"));
            return 1;
        }
    } else {
        unsigned int log_path_len = strlen(argv[0]) + 5;
        char *log_path = (char*)malloc(log_path_len);
        strcpy(log_path, argv[0]);
        strcat(log_path, ".log");
        audit_log = fopen(log_path, "w");
        if (!audit_log) {
            fprintf(stderr, "Fatal Python error: "
                "failed to open log file: %s\n", log_path);
            return 1;
        }
        free(log_path);
    }

    res = spython_main(argc, argv_copy, audit_log);

    /* Force again malloc() allocator to release memory blocks allocated
       before Py_Main() */
#ifdef Py_DEBUG
    (void)_PyMem_SetupAllocators("malloc_debug");
#  else
    (void)_PyMem_SetupAllocators("malloc");
#  endif

    for (i = 0; i < argc; i++) {
        PyMem_RawFree(argv_copy2[i]);
    }
    PyMem_RawFree(argv_copy);
    PyMem_RawFree(argv_copy2);
    return res;
}
#endif
