# formal_pledge

Have a format string vulnerability? Need the remote LIBC version? Fret not! **formal_pledge** looks for the `__libc_start_main` return from main, and checks its address against an offset database it builds using [libc-database](https://github.com/niklasb/libc-database) and pwntools [libc_start_main_return](https://docs.pwntools.com/en/stable/elf/elf.html#pwnlib.elf.elf.ELF.libc_start_main_return).

# Install
```bash
git clone https://github.com/k4lizen/formal_pledge.git
cd formal_pledge
pip install -e .
```
Then edit the `libc_database_location.py` file to set the [libc-database](https://github.com/niklasb/libc-database) database location.

# Usage
```python
import formal_pledge
# ...
formal_pledge.getlibc.run(exec_function, binary_elf)
```
`exec_function` is a function which takes the payload as the only parameter and returns the string the program returns, along with the process. `formal_pledge` will take care of closing the process.

On the first run, the `offsets.txt` file will be generated, this step is skipped in subsequent runs.

## Example
Can also be seen/run in the `example` directory.
```python
from pwn import *
import formal_pledge

def start():
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2])
    return process([exe])

def get_libc_send_payload(payload):
    p = start()
    p.recvuntil(b'>> ')
    p.sendline(payload)
    p.recvline()
    resp = p.recvline()
    return resp, p

# binary from https://ctf.nullcon.net/challenges
exe = './junior_formatter'
elff = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# python exploit.py REMOTE 52.59.124.14 5031
# python exploit.py 
formal_pledge.getlibc.run(get_libc_send_payload, elff)
```
To run:
```bash
cd example
chmod +x junior_formatter
python exploit.py
```