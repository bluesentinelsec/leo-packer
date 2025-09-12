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
    for (Py_ssize_t i = 0; i < n; i++) {
        x = (x * 1664525u + 1013904223u);
        buf[i] ^= (x >> 24) & 0xFF;  // Use only high byte, one LCG step per byte
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

