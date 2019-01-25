all: _netlink.so

_netlink.so: netlink.c setup.py
	python setup.py build
	ln -s -f build/*/_netlink.so .

clean:
	rm -rf *.pyc build *~

clean-all:
	rm -rf *.pyc *.so build *~