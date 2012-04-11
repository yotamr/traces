CCWRAP=/home/yotam/Code/core-system/traces/ccwrap.py
LDWRAP=/home/yotam/Code/core-system/traces/ldwrap.py
CC=$(CCWRAP) gcc
CXX=$(CCWRAP) g++
CXXFLAGS=-I..
LD=$(LDWRAP) ld
LDFLAGS=-L/home/yotam/Code/traces
all: demo

demo: demo.o
	$(CCWRAP) g++ $(LDFLAGS) demo.o ../libtraceuser.a -lrt -o demo

clean:
	rm demo.o demo