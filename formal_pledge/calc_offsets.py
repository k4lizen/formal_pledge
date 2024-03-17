from pwn import *
from os.path import isfile, isdir
import shutil

from formal_pledge.common import read_offsets_file, get_libc_folder, get_libcs, libc_name_to_path, offsets_path, tmp_offsets_path, adj_file

context.log_level = 'critical'
libc_folder = get_libc_folder()

def calc_offset(libcname):
    if not isfile(libcname):
        libcname = libc_name_to_path(libcname)
    if not isfile(libcname):
        print('file non-existant')
        return 0

    libc = {}
    try:
        libc = ELF(libcname, checksec=False)
        ret = libc.libc_start_main_return
        if ret != 0:
            print('FOUND: ', hex(ret))
        else:
            print('not found')
        return ret
    except Exception as ex:
        #   File "/usr/lib/python3/dist-packages/pwnlib/context/__init__.py", line 788, in arch
        # defaults = self.architectures[arch]
        #       ~~~~~~~~~~~~~~~~~~^^^^^^
        # KeyError: 'em_x86_64' 
        print('error: ' + str(ex))
        return 0

def calc_append():
    saved_libc_offsets = read_offsets_file()
    
    all_files = get_libcs()
    if len(all_files) == len(saved_libc_offsets):
        print('Everything inplace. Done.')
        return

    print('Clearing pwntools context.')
    context.clear()

    print(f'Found {len(all_files)} LIBC files.')

    files = []
    for file in all_files:
        if file not in saved_libc_offsets:
            files.append(file)

    n_saved = len(all_files) - len(files)

    non_zero = 0
    print(f'{n_saved} files already calculated. ("python calc_offsets.py HARD" or delete {offsets_path()} to calculate everything again)')
    print('Calculating and appending to offsets.txt.\n')
    with open(offsets_path(), 'r+') as offsets_file:
        # if this read is removed, mode should be changed to a
        if offsets_file.readlines()[-1][-1] != '\n':
            offsets_file.write('\n')

        for ind in range(len(files)):
            print(f"{n_saved + ind + 1}/{len(all_files)}( {files[ind]} ): ".ljust(60), end='')
            offset = calc_offset(files[ind])
            offsets_file.write(files[ind] + ' ' + hex(offset) + '\n')
            if offset != 0:
                non_zero += 1

    print(f'\nDONE (written to {offsets_path()}). {non_zero}/{len(files)} FOUND.')

def calc_from_scratch():
    print('Clearing pwntools context.')
    context.clear()

    files = get_libcs()

    non_zero = 0
    print(f'Calculating offsets and writing to {tmp_offsets_path()}.\n')
    with open(tmp_offsets_path(), 'w') as offsets_file:
        for ind in range(len(files)):
            print(f"{ind + 1}/{len(files)}( {files[ind]} ): ".ljust(60), end='')
            offset = calc_offset(files[ind])
            offsets_file.write(files[ind] + ' ' + hex(offset) + '\n')
            if offset != 0:
                non_zero += 1

    shutil.copy(tmp_offsets_path(), offsets_path())
    os.remove(tmp_offsets_path())
    print(f'\nDONE (written to {offsets_path()}). {non_zero}/{len(files)} FOUND.')

def calculate_offsets():
    try:
        libcs_path = get_libc_folder()
        if not isdir(libcs_path):
            print(f'LIBC database (https://github.com/niklasb/libc-database) path ({libcs_path}) not a directory. Edit {adj_file("libc_database_location.py")} to change the path.')
            exit(1)

        print(f'Getting LIBCs from {libcs_path}. Edit {adj_file("libc_database_location.py")} to change this.' )

        if args.HARD or not isfile(offsets_path()):
            calc_from_scratch()
        else:
            calc_append()
    except KeyboardInterrupt:
        save_msg = ''
        if isfile(tmp_offsets_path()):
            shutil.copy(tmp_offsets_path(), offsets_path())
            os.remove(tmp_offsets_path())
            save_msg = 'Saving tmp_offsets.txt -> offsets.txt. '
        print(f'\n\nKeyboard Interrupt (Ctrl+C). {save_msg}Quitting.')


if __name__ == "__main__":
    calculate_offsets()


"""
def print_func_with(functions, str):
    for key in functions:
        if str in key:
            print(functions[key])
    return 'nothing'    
    
def disass_line_offset(line):
    return int(line.split(':       ')[0].strip(), 16)

CALL_EXIT_LINE_DIST = 4 # how many lines before the exit call to look for the main call
# manually implements libc.libc_start_main_return
# returns zero on fail
def calc_offset_unused(libcname):
    if not isfile(libcname):
        libcname = libc_name_to_path(libcname)
    if not isfile(libcname):
        print('file non-existant')
        return 0

    libc = {}
    try:
        libc = ELF(libcname, checksec=False)
    except Exception as ex:
        #   File "/usr/lib/python3/dist-packages/pwnlib/context/__init__.py", line 788, in arch
        # defaults = self.architectures[arch]
        #       ~~~~~~~~~~~~~~~~~~^^^^^^
        # KeyError: 'em_x86_64' 
        print('pwntools couldnt load file: ' + str(ex))
        return 0

    main_caller = 0
    if '__libc_init_first' in libc.functions:
        main_caller = libc.functions['__libc_init_first'] # has different name in dynamic analysis (often __libc_start_call_main)
    elif '__libc_start_main'  in libc.functions:
        main_caller = libc.functions['__libc_start_main']
    else:
        print('__libc_init_first, __libc_start_main not found')
        libc.close()
        return 0
    
    if 'exit' not in libc.functions:
        print('exit not in available function symbols')
        libc.close()
        return 0

    exit = libc.functions['exit']

    exit_addr = exit.address
    init_first_disass = ""
    try:
        init_first_disass = libc.disasm(main_caller.address, 200) # __libc_init_first.size is 0x1 for some reason
    except Exception as ex:
        print('couldnt disassemble: ' + str(ex))
        libc.close()
        return 0

    disass_lines = init_first_disass.split('\n')
    
    init_exit_call_offset = 0
    init_exit_call_line = 0
    
    for line in disass_lines:
        if hex(exit_addr) in line:
            init_exit_call_offset = disass_line_offset(line)
            init_exit_call_line = disass_lines.index(line)
            # print('init call at offset: ', init_exit_call_offset, ' line: ', init_exit_call_line)
            break

    if init_exit_call_line == 0 or init_exit_call_offset == 0:
        print('couldnt find exit call')
        libc.close()
        return 0

    main_return_offset = 0
    ind = init_exit_call_line - 1
    while ind + CALL_EXIT_LINE_DIST >= init_exit_call_line:
        # print('candidate line: ', disass_lines[ind])
        if 'call' in disass_lines[ind]:
            main_return_offset = disass_line_offset(disass_lines[ind + 1])
            break

        ind -= 1

    if main_return_offset == 0:
        print('couldnt find main call in ', CALL_EXIT_LINE_DIST, ' lines before exit call')
        libc.close()
        return 0

    libc.close()
    print(' ' * 60 + ('FOUND offset: ' + hex(main_return_offset)))
    return main_return_offset
"""