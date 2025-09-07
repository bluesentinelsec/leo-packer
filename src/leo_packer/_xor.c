#define PY_SSIZE_T_CLEAN
#include <Python.h>

/*
 * Fast XOR stream cipher (LCG based).
 * Arguments: seed (int), data (bytearray or writable buffer).
 * Works in-place, returns None.
 */
static PyObject *
xor_stream_apply(PyObject *self, PyObject *args)
{
    unsigned int seed;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "IO!", &seed, &PyByteArray_Type, &obj)) {
        return NULL;
    }

    Py_ssize_t n = PyByteArray_Size(obj);
    unsigned char *buf = (unsigned char *)PyByteArray_AsString(obj);

    unsigned int x = seed;
    Py_ssize_t i = 0;

    while (i + 4 <= n) {
        x = (x * 1664525u + 1013904223u);
        buf[i]     ^= (x >> 24) & 0xFF;
        buf[i + 1] ^= (x >> 16) & 0xFF;
        buf[i + 2] ^= (x >> 8)  & 0xFF;
        buf[i + 3] ^= x & 0xFF;
        i += 4;
    }

    while (i < n) {
        x = (x * 1664525u + 1013904223u);
        buf[i] ^= (x >> 24) & 0xFF;
        i++;
    }

    Py_RETURN_NONE;
}

static PyMethodDef XorMethods[] = {
    {"xor_stream_apply", xor_stream_apply, METH_VARARGS,
     "Apply XOR stream cipher in place to a bytearray"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef xormodule = {
    PyModuleDef_HEAD_INIT,
    "_xor",   /* name of module */
    "C-accelerated XOR stream cipher", /* module doc */
    -1,
    XorMethods
};

PyMODINIT_FUNC
PyInit__xor(void)
{
    return PyModule_Create(&xormodule);
}

