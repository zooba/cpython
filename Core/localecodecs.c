#include "Python.h"

int
_Py_DecodeLocaleEx(
    const char *arg,
    char **u8str,
    size_t *u8len,
    const char **reason,
    int current_locale,
    _Py_error_handler errors)
{
    return -1;
}

int _Py_EncodeLocaleEx(
    const char *u8text,
    char **str,
    size_t *error_pos,
    const char **reason,
    int current_locale,
    _Py_error_handler errors)
{
    return -1;
}
