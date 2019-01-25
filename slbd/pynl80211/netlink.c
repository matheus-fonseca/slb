#include <Python.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

static PyObject *
nlbind(PyObject *self, PyObject *args, PyObject *keywds)
{
	int fd, ret, groups = 0;
	struct sockaddr_nl addr;
	static char *kwlist[] = {"fd", "groups", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, keywds, "i|i", kwlist, &fd, &groups))
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = groups;
	ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	if (ret) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
nlsend(PyObject *self, PyObject *args, PyObject *keywds)
{
	int fd, ret, flags = 0, msglen;
	struct sockaddr_nl addr;
	const char *msg;
	static char *kwlist[] = {"fd", "message", "flags", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, keywds, "is#|i", kwlist,
					 &fd, &msg, &msglen, &flags))
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	ret = sendto(fd, msg, msglen, flags, (struct sockaddr*)&addr, sizeof(addr));

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
nlrecvfrom(PyObject *self, PyObject *args)
{
	int fd, ret;
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	size_t bufs = 16384;
	char *buf;
	PyObject *retval;

	if (!PyArg_ParseTuple(args, "i|i", &fd, &bufs))
		return NULL;

	buf = calloc(1, bufs);
	if (!buf) {
		PyErr_NoMemory();
		return NULL;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	Py_BEGIN_ALLOW_THREADS
	ret = recvfrom(fd, buf, bufs, 0, (void*)&addr, &addrlen);
	Py_END_ALLOW_THREADS
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	retval = Py_BuildValue("(s#, (i, i))", buf, ret, addr.nl_pid, addr.nl_groups);
	free(buf);
	return retval;
}

static PyObject *
nlgetsockname(PyObject *self, PyObject *args)
{
	int fd, ret;
	struct sockaddr_nl addr;
	socklen_t addrlen;

	if (!PyArg_ParseTuple(args, "i", &fd))
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	ret = getsockname(fd, (struct sockaddr*)&addr, &addrlen);

	if (ret) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	if (addrlen != sizeof(addr)) {
		PyErr_SetString(PyExc_OSError, "getsockname() returned invalid size struct!");
		return NULL;
	}

	return Py_BuildValue("(ii)", addr.nl_pid, addr.nl_groups);
}

static PyMethodDef nl_methods[] = {
	{ "bind", (PyCFunction)nlbind, METH_VARARGS|METH_KEYWORDS, "bind a netlink socket" },
	{ "send", (PyCFunction)nlsend, METH_VARARGS|METH_KEYWORDS, "send a netlink message" },
	{ "recvfrom", nlrecvfrom, METH_VARARGS, "receive netlink messages" },
	{ "getsockname", nlgetsockname, METH_VARARGS, "get netlink socket name" },
	{}
};

PyMODINIT_FUNC
init_netlink(void)
{
	(void) Py_InitModule("_netlink", nl_methods);
}
