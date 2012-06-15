TRACES_ROOT_DIR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
CCWRAP=$(TRACES_ROOT_DIR)/ccwrap.py
LDWRAP=$(TRACES_ROOT_DIR)/ldwrap.py
CC=$(CCWRAP) gcc
CXX=$(CCWRAP) g++
CXXFLAGS=-I../include
LD=$(LDWRAP) ld
LDFLAGS=-L$(TRACES_ROOT_DIR)
all: demo

demo: demo.o shared-demo-1 shared-demo-2
	$(CCWRAP) g++ $(LDFLAGS) demo.o ../libtraceuser.a -lrt -L. -lshared-demo-1 -lshared-demo-2 -o demo

shared-demo-1.o: CXXFLAGS=-I ../include -fPIC 
shared-demo-2.o: CXXFLAGS=-I ../include -fPIC
shared-demo-1: shared-demo-1.o
	$(CCWRAP) g++ $(LDFLAGS) -fPIC -shared shared-demo-1.o ../libtraceuser.a -lrt -o libshared-demo-1.so

shared-demo-2: shared-demo-2.o
	$(CCWRAP) g++ $(LDFLAGS) -fPIC -shared shared-demo-2.o ../libtraceuser.a -lrt -o libshared-demo-2.so

clean:
	rm -f *.so *.o demo
