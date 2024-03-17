from pwn import *
import shutil
from os import listdir
from os.path import isfile, join

import formal_pledge

context.log_level = 'critical'     

def get_interpreter(libc_name):
    interpreter_filename = com.libc_name_to_interp_name(libc_name)
    interpreter_path = os.path.join(interpreter_folder, interpreter_filename)
    libc_path = os.path.join(libc_folder, libc_name)

    if isfile(interpreter_path):
        print('already downloaded')
        return

    tmp_down_folder = libcdb.download_libraries(libc_path)
    if tmp_down_folder == None:
        print('package not found')
        return

    fetched_files = [f for f in listdir(tmp_down_folder) if (isfile(join(tmp_down_folder, f)))]
    for name in fetched_files:
        if 'ld-linux' in name:
            shutil.copy(os.path.join(tmp_down_folder, name), interpreter_path)

            print("DOWNLOADED")
            return
    print('package found but no interpreter')


# libc_folder, interpreter_folder = com.get_config_folders()

os.makedirs(os.path.dirname(interpreter_folder), exist_ok=True)
print('Using ', libc_folder, ' libc files to download interpreters into ', interpreter_folder)
files = com.get_libcs()
print(len(files), ' libc (or musl) files detected')

for ind in range(len(files)):
    print(f"{ind + 1}/{len(files)}( {files[ind]} ): ".ljust(60), end='')
    get_interpreter(files[ind])
