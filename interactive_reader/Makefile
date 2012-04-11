all: ../trace_parser.h
	h2xml  -c -I.. trace_parser.h -o _trace_parser_ctypes.xml
	xml2py -k f -k e -k s _trace_parser_ctypes.xml > _trace_parser_ctypes.py
	rm _trace_parser_ctypes.xml