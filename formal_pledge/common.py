from os import listdir
from os.path import isfile, join, abspath, dirname
from inspect import getsourcefile

import tomllib

from formal_pledge.libc_database_location import libc_database_folder

def offsets_path():
    return adj_file('offsets.txt')

def tmp_offsets_path():
    return adj_file('tmp_offsets.txt')

def adj_file(name):
    return join(get_current_folder(), name)

def get_current_folder():
    return dirname(abspath(getsourcefile(lambda:0)))

# list, string
def only_with(filenames, what):
    ret_files = []
    for filename in filenames:
        if what in filename:
            ret_files.append(filename)
    return ret_files

def only_so(filenames):
    return only_with(filenames, '.so')

def get_libcs():
    onlyfiles = [f for f in listdir(libc_database_folder) if (isfile(join(libc_database_folder, f)))]
    files = only_so(onlyfiles)
    return files

def get_libc_folder():
    return libc_database_folder

def libc_name_to_interp_name(libcname):
    return "ld_for_" + libcname

def interp_name_to_path(interpname):
    return join(interpreter_folder, interpname)

def libc_name_to_path(libcname):
    return join(libc_database_folder, libcname)

def libc_name_to_interp_path(libcname):
    return interp_name_to_path(libc_name_to_interp_name(libcname))

def read_offsets_file():
    saved_libc_offsets = {}
    already_saved = open(offsets_path(), 'r')
    saved_lines = already_saved.readlines()
    for line in saved_lines:
        sp = line.split(' ')
        saved_libc_offsets[sp[0]] = int(sp[1], 16)
    already_saved.close()
    return saved_libc_offsets