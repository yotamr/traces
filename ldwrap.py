#!/bin/env python2.7
# Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
#    Sponsored by infinidat (http://infinidat.com)
#   
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import sys
import os
import subprocess
import re

OBJDUMP_PATH = os.getenv('OBJDUMP_PATH', 'objdump')

def spawn(args):
    return os.spawnvp(os.P_WAIT, args[0], args)

def get_linked_objects(ld_out):
    objs = []
    for line in ld_out.split("\n"):
        if line.endswith("succeeded") and ("attempt to open" in line or "Attempt to open" in line):
            start_index = line.find("attempt to open")
            if start_index == -1:
                start_index = line.find("Attempt to open")

            line = line[start_index:]    
            obj_name = line[len("attempt to open "):-len(" succeeded")]
            if not obj_name.endswith((".a", ".o")):
                continue
            
            objs.append(obj_name)

    return objs

def get_section_names(objdump_output):
    section_names = re.findall("[0-9] (\.[\.|\w|:]+)", objdump_output)
    unfiltered_sections = list(set(section_names))

    all_sections = [section_name
                    for section_name in unfiltered_sections
                    if section_name.startswith((".gnu.linkonce.type.enum.", ".gnu.linkonce.type.struct.", ".gnu.linkonce.type.union."))]
    filtered_sections = set([section_name[:section_name.rfind(".")]
                             for section_name in all_sections])

    return list(filtered_sections)
        
def get_type_sections(object_files):
    cmdline = "%s -h %s" % (OBJDUMP_PATH, ' '.join(object_files))
    objdump_output = os.popen(cmdline).read()
    type_section_names = get_section_names(objdump_output)
    return type_section_names

def get_type_information_section_script(args, linked_objects):
    type_section_names = get_type_sections(linked_objects)
    linker_script_addition = []
    for type_section_name in type_section_names:
        _section_size_name = type_section_name.replace(".", "_") + "_size"
        additions = ["%s : {" % (type_section_name,),
                     "    %s = .;" % (_section_size_name),
                     "    *(%s)" % (type_section_name + ".ptr"),
                     "    *(%s)" % (type_section_name + ".data"),
                     "    *(%s)" % (type_section_name + ".defs"),
                     "}" ]
        linker_script_addition.extend(additions)

    return linker_script_addition

def add_trace_directives_to_script(internal, linker_script, verbose_output, args):
    linked_objects = get_linked_objects(verbose_output)
    ldscript = []
    i = -1
    if internal:
        for line in linker_script.splitlines():
            if line.startswith('using internal linker script:'):
                i = 0
                continue
            if i == -1:
                continue
            i += 1
            if i > 1:
                if line.startswith('========'):
                    break
                ldscript.append(line)
    else:
        ldscript = linker_script.splitlines()

    # Inject our sections
    type_information_sections = get_type_information_section_script(args, linked_objects)
    prefix = '  .data1 '
    additions = [
        ". = ALIGN(32);",
        ".static_log_information : {",
        "    PROVIDE(__static_log_information_start = .);",
        "    *(.static_log_data)",
        "    PROVIDE(__static_log_information_end = .);",
        "}",
        
    ]

    additions.append("PROVIDE(__type_information_start = .);")
    additions.extend(type_information_sections)
    additions.append(""".gnu.linkonce.null_type : {
    *(.gnu.linkonce.null_type)
    }""")

    for index, line in enumerate(ldscript):
        if line.startswith(prefix):
            ldscript = ldscript[:index] + additions + ldscript[index:]
            break

    return ldscript

def get_linker_script(linker_direct, args):
    # Get ld script
    if linker_direct:
        vargs = args + ["--verbose"]
    else:
        vargs = args + ["-Xlinker", "--verbose"]


    s = subprocess.Popen(vargs, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = s.stdout.read()
    s.wait()

    if linker_direct:
        return add_trace_directives_to_script(True, output, output, args)

    for arg in vargs:
        if '-T' in arg:
            filename = arg.split(',')[-1]
            return add_trace_directives_to_script(False, file(filename).read(), output, args)

    return add_trace_directives_to_script(True, output, output, args)

def set_linker_script_filename(linker_direct, linker_script, xargs):
    if linker_direct:
        xargs.append('-T')
        xargs.append(script_file)
        return

    for index, arg in enumerate(xargs):
        if '-T' in arg:
            split_arg = arg.split(',')
            split_arg[-1] = linker_script
            xargs[index] = ','.join(split_arg)
            return
        
    xargs.append('-Xlinker')
    xargs.append('-T')
    xargs.append('-Xlinker')
    xargs.append(linker_script)
     
def main():
    args = sys.argv[1:]
    linker_direct = True
    if 'gcc' in args[0] or 'g++' in args[0]:
        linker_direct = False

    if '-o' not in args:
        ret = spawn(args)
        return ret
    
    linker_script_with_additions = get_linker_script(linker_direct, args)

    xargs = list(args)
    output_file = xargs[args.index('-o') + 1]
    script_file = output_file + '.lds'
    f = open(script_file, 'w')
    for line in linker_script_with_additions:
        if ' *(.data .data.* .gnu.linkonce.type.*)' in line:
            line = '*(.data .gnu.linkonce.type.*)'

        f.write(line + '\n')
    f.close()

    set_linker_script_filename(linker_direct, script_file, xargs)
    try:
        ret = spawn(xargs)
        return ret
    finally:
        pass
        #os.unlink(script_file)


if __name__ == "__main__":
    sys.exit(main())

