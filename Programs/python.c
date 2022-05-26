/* Minimal main program -- everything is loaded from the library */

#include "Python.h"

#ifdef MS_WINDOWS
#include <windows.h>
#include <io.h>
#include <fcntl.h>

typedef struct _cache_item {
    HANDLE hHint;
    FILE_ID_DESCRIPTOR id;
} cache_item;


static PyObject *
open_code(PyObject *opath, PyObject **cache)
{
    HANDLE hFile = NULL;
    if (!*cache) {
        *cache = PyDict_New();
    }

    PyObject *cached = PyDict_GetItem(*cache, opath);
    if (cached != NULL) {
        cache_item *item = (cache_item *)PyBytes_AsString(cached);
        hFile = OpenFileById(item->hHint, &item->id, GENERIC_READ, FILE_SHARE_READ,
            NULL, 0);
        Py_DECREF(cached);
    }


    if (!hFile) {
        wchar_t path[32768];
        Py_ssize_t pathLen = PyUnicode_AsWideChar(opath, path, 32767);
        if (pathLen < 0) {
            return NULL;
        }

        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            PyErr_SetFromWindowsErr(0);
            return NULL;
        }

        HANDLE hHint = ReOpenFile(hFile, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);

        wchar_t *sep1 = wcsrchr(path, L'\\');
        wchar_t *sep2 = wcsrchr(path, L'/');
        if (!sep1 || (sep2 && sep2 > sep1)) {
            sep1 = sep2;
        }
        wcscpy(sep1, L"\\*");

        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(path, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t *ext = wcsrchr(findData.cFileName, L'.');
                if (!ext || 0 != wcsncmp(ext, L".py", 3)) {
                    continue;
                }

                wcscpy(&sep1[1], findData.cFileName);

                FILE_ID_INFO idInfo;
                cache_item item;
                HANDLE hFile2 = CreateFileW(path, FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
                GetFileInformationByHandleEx(hFile2, FileIdInfo, &idInfo, sizeof(idInfo));
                DuplicateHandle(GetCurrentProcess(), hHint,
                    GetCurrentProcess(), &item.hHint, 0, FALSE, DUPLICATE_SAME_ACCESS);
                item.id.Type = ExtendedFileIdType;
                item.id.ExtendedFileId = idInfo.FileId;
                CloseHandle(hFile2);

                PyObject *key = PyUnicode_FromWideChar(path, -1);
                PyObject *value = PyBytes_FromStringAndSize((unsigned char*)&item, sizeof(item));
                PyDict_SetItem(*cache, key, value);
                Py_DECREF(key);
                Py_DECREF(value);
            } while (FindNextFileW(hFind, &findData));
        }
    }

    PyObject *io;
    if (!(io = PyImport_ImportModule("_io"))) {
        CloseHandle(hFile);
        return NULL;
    }

    PyObject *stream = PyObject_CallMethod(io, "FileIO", "i",
        _open_osfhandle((intptr_t)hFile, _O_RDONLY));
    Py_DECREF(io);

    return stream;
}


int
wmain(int argc, wchar_t **argv)
{
    PyObject *cache_dict = NULL;
    PyFile_SetOpenCodeHook(open_code, &cache_dict);
    int r = Py_Main(argc, argv);
    return r;
}
#else
int
main(int argc, char **argv)
{
    return Py_BytesMain(argc, argv);
}
#endif
