CFLAGS=-I. -c -Wall -g -fPIC -pg
LIBTRACE_OBJS=trace_metadata_util.o trace_parser.o halt.o trace_user.o cached_file.o
LIBTRACEUSER_OBJS=trace_metadata_util.o trace_user.o halt.o
all: libtrace libtraceuser simple_trace_reader trace_dumper trace_instrumentor interactive_reader
trace_dumper: $(LIBTRACE_OBJS) trace_dumper/trace_dumper.o trace_dumper/filesystem.o trace_user_stubs.o
	gcc -L.  trace_dumper/filesystem.o trace_dumper/trace_dumper.o trace_user_stubs.o -ltrace  -o trace_dumper/trace_dumper -lrt

libtrace: $(LIBTRACE_OBJS)
	ar rcs libtrace.a trace_metadata_util.o cached_file.o trace_parser.o halt.o  
	gcc -shared -g cached_file.o trace_metadata_util.o trace_parser.o halt.o -o traces.so

libtraceuser: $(LIBTRACEUSER_OBJS)
	ar rcs libtraceuser.a trace_metadata_util.o trace_user.o halt.o

simple_trace_reader: $(LIBTRACE_OBJS) trace_reader/simple_trace_reader.o
	gcc -L. trace_reader/simple_trace_reader.o -ltrace -o trace_reader/simple_trace_reader -pg

interactive_reader: trace_parser.h
	h2xml  -c -I. trace_parser.h -o _trace_parser_ctypes.xml
	xml2py -k f -k e -k s _trace_parser_ctypes.xml > interactive_reader/_trace_parser_ctypes.py
	rm _trace_parser_ctypes.xml

trace_instrumentor/trace_instrumentor.o: CXXFLAGS := $(shell llvm-config --cxxflags)
trace_instrumentor/trace_instrumentor.o: LDFLAGS := $(shell llvm-config --libs --ldflags)
trace_instrumentor: trace_instrumentor/trace_instrumentor.o
	gcc $(LDFLAGS) -shared trace_instrumentor/trace_instrumentor.o  -o trace_instrumentor/trace_instrumentor.so

clean:
	rm -f *.o trace_reader/simple_trace_reader.o trace_reader/simple_trace_reader trace_dumper/*.o trace_instrumentor/*.o trace_instrumentor/*.so trace_dumper/trace_dumper trace_reader/trace_reader *so *.a
