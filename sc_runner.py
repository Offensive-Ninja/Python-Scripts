#!/usr/bin/env python3
from ctypes import (CDLL, c_void_p, c_size_t, c_int, c_long, memmove, CFUNCTYPE, cast, pythonapi)
from ctypes.util import ( find_library)
from sys import exit

#
# This is a python3 version of the python shellcode loader by Sektor 7
# https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md
# 
# Uses their basic print shellcode
#
PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC=0x04
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
ENOMEM = -1

SHELLCODE = b'\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x31\xd2\x48\x83\xc2\x15\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x45\x78\x20\x6e\x69\x68\x69\x6C\x67\x20\x6E\x69\x68\x69\x6C\x20\x66\x69\x74\x21\x0a'

libc = CDLL(find_library('c'))
mmap = libc.mmap

mmap.restype = c_void_p

page_size = pythonapi.getpagesize()

sc_size = len(SHELLCODE)

mem_size = page_size * (1 + sc_size // page_size)

cptr = mmap(0, mem_size, PROT_READ|PROT_WRITE | PROT_EXEC, MAP_PRIVATE|


MAP_ANONYMOUS, -1, 0)

if cptr == ENOMEM: exit(' mmap() memory allocation error')

if sc_size <= mem_size:
    memmove(cptr, SHELLCODE, sc_size)
    sc = CFUNCTYPE(c_void_p, c_void_p)
    call_sc = cast(cptr, sc)
    call_sc(None)