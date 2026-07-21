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

// Monero merkle root for one miner, fused into a single call:
// extra is spliced over the tail of the miner-tx prefix,
// tx hash = keccak(keccak(prefix) || rct_hash || 32 zero bytes),
// then the precomputed main branch (concatenated 32-byte nodes) is folded in.
// Replaces 8+ per-miner keccak_256 round-trips on the pool broadcast path.
static PyObject* keccak_merkle_root(PyObject *self, PyObject *args) {
    const char *prefix, *extra, *rct, *branch;
    Py_ssize_t prefix_len, extra_len, rct_len, branch_len;
    if (!PyArg_ParseTuple(args, "y#y#y#y#", &prefix, &prefix_len, &extra, &extra_len,
                          &rct, &rct_len, &branch, &branch_len))
        return NULL;

    if (prefix_len > 4096 || extra_len > prefix_len || rct_len != 32 || branch_len % 32 != 0) {
        PyErr_SetString(PyExc_ValueError, "Buffer length is not correct");
        return NULL;
    }

    uint8_t buf[4096];
    memcpy(buf, prefix, (size_t)(prefix_len - extra_len));
    memcpy(buf + prefix_len - extra_len, extra, (size_t)extra_len);
    ethash::hash256 h = ethash::keccak256(buf, (size_t)prefix_len);

    uint8_t cat[96];
    memcpy(cat, h.bytes, 32);
    memcpy(cat + 32, rct, 32);
    memset(cat + 64, 0, 32);
    h = ethash::keccak256(cat, 96);

    for (Py_ssize_t i = 0; i < branch_len; i += 32) {
        memcpy(cat, h.bytes, 32);
        memcpy(cat + 32, branch + i, 32);
        h = ethash::keccak256(cat, 64);
    }

    return PyBytes_FromStringAndSize((const char*)h.bytes, 32);
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
        {"keccak_merkle_root", (PyCFunction)keccak_merkle_root, METH_VARARGS},
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
