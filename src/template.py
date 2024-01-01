#!/usr/bin/env python3

from pwn import *

context.terminal = ['gnome-terminal', '--']
context.binary = binary = {bin_path}
context.update(arch='x86_64')

{bindings}

def conn():
    if args.REMOTE:
        r = remote("addr", 1234)
    else:
        r = process(binary)
        gdb.attach(r)
    return r

def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
