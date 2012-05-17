TRACES_ROOT_DIR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
CCWRAP=$(TRACES_ROOT_DIR)/ccwrap.py
LDWRAP=$(TRACES_ROOT_DIR)/ldwrap.py
CC=$(CCWRAP) gcc
CXX=$(CCWRAP) g++
CXXFLAGS=-I../include
LD=$(LDWRAP) ld
LDFLAGS=-L$(TRACES_ROOT_DIR)
all: demo

traced_so: traced_so.o
	$(CCWRAP) g++ -fPIC -shared traced_so.o -o libtraced.so
demo: demo.o traced_so
	$(CCWRAP) g++ $(LDFLAGS) demo.o ../libtraceuser.a -lrt -L. -ltraced -o demo

clean:
	rm demo.o demo
