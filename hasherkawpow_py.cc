#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03090000
#include <Python.h>
#include <stdint.h>
#include "ethash.h"
#include "ethash.hpp"
#include "progpow.hpp"
#include "keccak.hpp"
#include "uint256.h"
#include "helpers.hpp"

static PyObject* keccak_256(PyObject *self, PyObject *args) {
    const char* buf;
    Py_ssize_t buf_len;
    if (!PyArg_ParseTuple(args, "y#", &buf, &buf_len))
        return NULL;

    const ethash::hash256 hash = ethash::keccak256((const uint8_t*)buf, (size_t)buf_len);

    PyObject *hash_py = PyBytes_FromStringAndSize((const char *)&hash, sizeof(ethash::hash256));
    return hash_py;
}

static ethash::epoch_context_ptr context{nullptr, nullptr};

static PyObject* pow(PyObject *self, PyObject *args) {
    const char* header_hash_buf;
    Py_ssize_t header_hash_len;
    const char* nonce64_buf;
    Py_ssize_t nonce64_len;
    int block_height;
    if (!PyArg_ParseTuple(args, "y#y#i", &header_hash_buf, &header_hash_len, &nonce64_buf, &nonce64_len, &block_height))
        return NULL;

    if (header_hash_len != 32 || nonce64_len != 8) {
        PyErr_SetString(PyExc_ValueError, "Buffer length is not correct");
        return NULL;
    }

    const ethash::hash256* header_hash_ptr = (const ethash::hash256*)header_hash_buf;
    uint64_t nonce64 = *(const uint64_t*)nonce64_buf;
    ethash::hash256 mix_out;
    ethash::hash256 hash_out;

    const auto epoch_number = ethash::get_epoch_number(block_height);

    if (!context || context->epoch_number != epoch_number)
        context = ethash::create_epoch_context(epoch_number);

    progpow::hash_one(*context, block_height, header_hash_ptr, nonce64, &mix_out, &hash_out);

    PyObject *hash_py = PyBytes_FromStringAndSize((const char *)&hash_out, sizeof(ethash::hash256));
    PyObject *mix_py = PyBytes_FromStringAndSize((const char *)&mix_out, sizeof(ethash::hash256));
    PyObject *tuple = Py_BuildValue("(OO)", hash_py, mix_py);
    Py_DECREF(hash_py);
    Py_DECREF(mix_py);
    return tuple;
}

static PyObject* pow_light(PyObject *self, PyObject *args) {
    const char* header_hash_buf;
    Py_ssize_t header_hash_len;
    const char* nonce64_buf;
    Py_ssize_t nonce64_len;
    const char* mix_hash_buf;
    Py_ssize_t mix_hash_len;
    int block_height;
    if (!PyArg_ParseTuple(args, "y#y#iy#", &header_hash_buf, &header_hash_len, &nonce64_buf, &nonce64_len, &block_height, &mix_hash_buf, &mix_hash_len))
        return NULL;

    if (header_hash_len != 32 || nonce64_len != 8 || mix_hash_len != 32) {
        PyErr_SetString(PyExc_ValueError, "Buffer length is not correct");
        return NULL;
    }

    const ethash::hash256* header_hash_ptr = (const ethash::hash256*)header_hash_buf;
    uint64_t nonce64 = *(const uint64_t*)nonce64_buf;
    const ethash::hash256* mix_hash_ptr = (const ethash::hash256*)mix_hash_buf;
    ethash::hash256 hash_out;

    const auto epoch_number = ethash::get_epoch_number(block_height);

    if (!context || context->epoch_number != epoch_number)
        context = ethash::create_epoch_context(epoch_number);

    progpow::hash_one_light(*context, block_height, header_hash_ptr, nonce64, mix_hash_ptr, &hash_out);

    PyObject *hash_py = PyBytes_FromStringAndSize((const char *)&hash_out, sizeof(ethash::hash256));
    return hash_py;
}

static PyMethodDef methods[] = {
        {"keccak_256", (PyCFunction)keccak_256, METH_VARARGS},
        {"pow", (PyCFunction)pow, METH_VARARGS},
        {"pow_light", (PyCFunction)pow_light, METH_VARARGS},
        {NULL, NULL}
};

static struct PyModuleDef module = {
        PyModuleDef_HEAD_INIT,
        "kawpow",
        NULL,
        -1,
        methods
};

PyMODINIT_FUNC PyInit_kawpow(void) {
    return PyModule_Create(&module);
}
