#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}

env = dict(LD_PRELOAD="%s:%s" % (ld.path, libc.path))

def conn():
    if args.GDB:
        return gdb.debug(exe.path, env=env, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote("addr", 1337)
    else:
        return process(exe.path, env=env)

gdbscript = """
continue
"""

def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
