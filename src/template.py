#!/usr/bin/env python2

from pwn import *

BINDINGS
context.binary = exe


def conn():
    if args.LOCAL:
        return process(PROC_ARGS)
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
