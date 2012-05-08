#!/usr/bin/python

from cStringIO import StringIO
import tokenize
import re
import sys
import string
def _get_format_string(tokens, entire_string):
    for i, (toknum, tokval, start, end, _) in enumerate(tokens):
        if toknum == tokenize.STRING:
            new_tokens = entire_string[end[1]:].split(',')
            new_tokens[-1] = new_tokens[-1].replace(');', '')
            return tokval, new_tokens[1:], start[1]

def get_formats(format_string):
    prev_index = 0
    while True:
        index = format_string.find('%', prev_index)
        if index == -1:
            return

        fmt_len = 1
        while True:
            if format_string[index + fmt_len] not in string.ascii_lowercase:
                break
            fmt_len += 1
            
        prev_index = index + fmt_len
        yield format_string[index:index + fmt_len], index, prev_index

def find_closing_bracket(s, pos):
    nest = 0
    while pos < len(s):
        if s[pos] == '(':
            nest += 1
        elif s[pos] == ')':
            if nest == 0:
                return pos
            nest -= 1
        pos += 1
    return None
     
def convert_format_line_to_arg_list(macro_call):
    tokens = list(tokenize.generate_tokens(StringIO(macro_call).readline))
    format_string, tokens, start = _get_format_string(tokens, macro_call)
    format_string = format_string[1:]
    new_call = macro_call[:start]
    new_format_string = []
    prev_fmt_index = 0

    for format_index, (format, start_index, end_index) in enumerate(get_formats(format_string)):
        new_format_string.append('"')
        new_format_string.append(format_string[prev_fmt_index:start_index].strip())
        new_format_string.append('", ')
        new_format_string.append(str(tokens[format_index]))
        if format_index + 1!= len(tokens) or (format_index + 1 == len(tokens) and format_string[end_index + 1:-1].strip()):
            new_format_string.append(', ')
            
        prev_fmt_index = end_index + 1

    if format_string[prev_fmt_index:-1].strip():
        new_format_string.append('"' + format_string[prev_fmt_index:-1].strip() + '"')

    new_format_string.append(');')
    return new_call + ''.join(new_format_string)

def convert_file(filename, macro_name):
    data = file(filename).read()
    new_data = []
    prev_index = 0
    while True:
        index = data.find(macro_name, prev_index)
        if index == -1:
            break

        end_index = find_closing_bracket(data, index + len(macro_name))
        macro_call = data[index:end_index + 2]
        if not '%' in macro_call:
            new_data.append(data[prev_index:end_index + 2])
            prev_index = end_index + 2
            continue

        macro_call = ' '.join(macro_call.replace("\n", "").strip().split())
        new_call = convert_format_line_to_arg_list(macro_call)
        new_data.append(data[prev_index:index])
        new_data.append(new_call)
        prev_index = end_index + 2
        
    new_data.append(data[prev_index:])
    new_data = ''.join(new_data)
    if new_data != data:
        print 'fixed up', filename
        file(filename, 'wb').write(''.join(new_data))
    else:
        print 'no fixups needed for', filename
        
if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) < 2:
        print 'Usage: python fixup_traces.py MACRO_NAME [file1] [file2]'
        print 'Example: python fixup_traces.py "XN_LOGF(" modules/ssd/devices/ssd_config.cpp'

    for filename in args[1:]:
        convert_file(filename, args[0])
