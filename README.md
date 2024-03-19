# formal_pledge

Have a format string vulnerability? You're in the right place!
+ Get the remote LIBC version
+ Quickly get the perfect string to leak all relevant regions! (local only, ASLR off)

To get the LIBC version, **formal_pledge** looks for the `__libc_start_main` return from main, and checks its address against an offset database it builds using [libc-database](https://github.com/niklasb/libc-database) and pwntools [libc_start_main_return](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.libc_start_main_return).

# Install
```bash
git clone https://github.com/k4lizen/formal_pledge.git
cd formal_pledge
pip install -e .
```
Then edit the `formal_pledge/libc_database_location.py` file to set the [libc-database](https://github.com/niklasb/libc-database) database location.

# Usage
The idea is to first find the remote LIBC version with `.libcv`, then patch the binary using something like [pwninit](https://github.com/io12/pwninit/), and then leak the binary/stack(/libc) offsets with `.leak` since ASLR needs to be turned off for it.
## Getting LIBC Remote Version
```python
import formal_pledge
# ...
formal_pledge.libcv(exec_function, binary_elf)
```
`exec_function` is a function which takes the payload as the only parameter. Returns the printed format string and the process object (see example). `formal_pledge` will take care of closing the process.

If a `process()` is supplied, exact offset will be calculated with [pwntools elf.libs()](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.libs), otherwise if the object is `remote()` only the last 12 bits of the address will be compared.

On the first run, the `offsets.txt` file may need to be populated, this step is skipped in subsequent runs (unless new libc files are added to the database).
## Leaking Binary, Stack and LIBC
```python
import formal_pledge
# ...
formal_pledge.leak(exec_function, binary_elf)
```
`exec_function` is a function which takes the payload as the only parameter. Returns the printed format string and the process object (see example). `formal_pledge` will take care of closing the process. The process needs to be local and have ASLR turned off.

To check which address belongs to which region (if any), some heuristic about usual binary and stack placement is used (located in `formal_pledge/leak_regions.py`), while libc is targeted using [pwntools elf.libs()](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.libs).

# Examples
Can be seen/run in the `example/` directory.
## Leaking LIBC Remote Version
```python
from pwn import *
import formal_pledge

def start():
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2])
    return process([exe])

def send_payload(payload):
    p = start()
    p.recvuntil(b'>> ')
    p.sendline(payload)
    p.recvline()
    resp = p.recvline()
    return resp, p

# binary from https://ctf.nullcon.net/challenges
exe = './junior_formatter'
elff = context.binary = ELF(exe, checksec=False)

# python exploit.py REMOTE 52.59.124.14 5031
# python exploit.py 
formal_pledge.libcv(send_payload, elff)
```
To run:
```bash
cd example
chmod +x junior_formatter
python exploit_libc.py
```
## InfoLeaking Binary, Stack and LIBC
```python
from pwn import *
import formal_pledge

def send_payload(payload):
    p = process([exe], aslr=False)
    p.recvuntil(b'>> ')
    p.sendline(payload)
    p.recvline()
    resp = p.recvline()
    return resp, p

# binary from https://ctf.nullcon.net/challenges
exe = './junior_formatter'
elff = context.binary = ELF(exe, checksec=False)

# python exploit.py 
formal_pledge.leak(send_payload, elff)
```
To run:
```bash
cd example
chmod +x junior_formatter
python exploit_leak.py
```