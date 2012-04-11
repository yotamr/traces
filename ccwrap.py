#!/usr/bin/env python2.7
# Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
#    Sponsored by infinidat (http://infinidat.com)
   
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import sys
import os
import re
import subprocess

from ldwrap import main as ldmodwrap_main
plugin_path = os.getenv('TRACE_INSTRUMENTOR', os.path.join(os.path.dirname(sys.argv[0]), "trace_instrumentor/trace_instrumentor.so"))
clang_path = "/usr/local/bin/clang"

def spawn(args):
    return os.spawnvp(os.P_WAIT, args[0], args)

class Error(Exception):
    pass

def translate(pp_file, out_pp_file, language, cflags):
    if language == 'c++':
        args = [clang_path, "-cc1", "-Wno-attributes", "-fcolor-diagnostics", "-fgnu-keywords", "-std=gnu++11", "-x", "c++", "-fcxx-exceptions", pp_file, "-o", out_pp_file]
    else:
        args = [clang_path, "-cc1", "-Wno-attributes", "-fcolor-diagnostics", "-fgnu-keywords", "-std=gnu99", pp_file, "-o", out_pp_file]

    args.extend(cflags)
    args.extend(["-load", plugin_path, "-plugin", "trace-instrument"])
    print ' '.join(args)
    try:
        output = subprocess.check_output(args, stderr = subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        print 'clang returned', e.returncode
        print 'Args:', ' '.join(args)
        print 'Output:', e.output
        return 1
    
    return 0

def maybe_translate(pp_file, out_pp_file, language, cflags):
    try:
        return translate(pp_file, out_pp_file, language, cflags)
    except Error, e:
        print e.args[0]
        return -1


def get_cflags(args):
    cflags = []
    for i, arg in enumerate(args):
        if arg.startswith(("-I")):
            if arg == "-I":
                cflags.append(arg)
                cflags.append(args[i + 1])
            else:
                cflags.append(arg)

    return cflags
    
def main():
    args = sys.argv[1:]
    if '-c' not in args:
        return ldmodwrap_main()

    c_index = -1
    for i, p in enumerate(args):
        if p.endswith('.c') or p.endswith("cpp"):
            c_index = i
            break

    if c_index == -1:
        ret = spawn(args)
        return ret

    cpp_args = list(args)
    cpp_args[args.index('-c')] = '-E'
    c_file = args[c_index]
    cflags = get_cflags(args)
    if p.endswith('cpp'):
        language = 'c++'
    else:
        language = 'c'

    if '-o' not in args:
        o_file = c_file + '.o'
        pp_file = o_file + '.pp'
        cpp_args.append('-o')
        cpp_args.append(pp_file)
    else:
        o_index = args.index('-o') + 1
        o_file = cpp_args[o_index]
        pp_file = o_file + '.pp'
        cpp_args[o_index] = pp_file

    # Hack for dealing with sources that use _GNU_SOURCE
    if '#define _GNU_SOURCE' in file(c_file).read():
        cpp_args.extend(["-w", "-D", "_GNU_SOURCE"])
        
    cpp_args.extend(["-D", "__TRACE_INSTRUMENTATION"])
    cpp_args.extend(["-include", os.path.join(os.path.dirname(sys.argv[0]),  "trace_lib.h")])
    cpp_args.extend(["-include", os.path.join(os.path.dirname(sys.argv[0]),  "trace_user.h")])

    out_pp_file = pp_file + ".i"
    ret = spawn(cpp_args)
    print out_pp_file, 'crap'
    print ' '.join(cpp_args)
    if ret:
        return ret
    clang_ret = 0;

    try:
        clang_ret = maybe_translate(pp_file, out_pp_file, language, cflags)
        if clang_ret != 0:
            return -1

        comp_args = []
        comp_args.extend(list(args))

        if '-o' not in comp_args:
            o_file = os.path.splitext(c_file)[0] + '.o'
            comp_args.extend(['-o', o_file])

        comp_args[c_index] = out_pp_file
        ret = spawn(comp_args)
        return ret;
    finally:
        os.unlink(pp_file)
        if os.getenv("TRACE_NO_UNLINK_PPFILE", "") == "":
            # Delete the pp.i file only if the clang invocation was successful
            pass
            if clang_ret == 0:
               os.unlink(out_pp_file)

if __name__ == "__main__":
    sys.exit(main())
