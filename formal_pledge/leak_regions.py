# 32-bit reference: tamu19_pwn1/pwn1
# 64-bit reference: nullcon24/junior_formatter 

differ_mask = {
    64: 0xffffffffff000000,
    32: 0xff000000,
}

# binary end not really consistent
binary_start = {
    64: 0x555555554000,
    32: 0x56555000
}
stack_start = {
    64: 0x7ffffffde000,
    32: 0xfffdd000
}
# stack end somewhat consistent
stack_end = {
    64: 0x7ffffffff000,
    32: 0xffffe000
}
binary_start_d = {
    32: binary_start[32] & differ_mask[32],
    64: binary_start[64] & differ_mask[64]
}
stack_start_d = {
    32: stack_start[32] & differ_mask[32],
    64: stack_start[64] & differ_mask[64]
}
stack_end_d = {
    32: stack_end[32] & differ_mask[32],
    64: stack_end[64] & differ_mask[64]
}
# libc calculated dynamically via pwntools (end is ambigous though)