#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}


def conn():
    if args.LOCAL:
        return process({proc_args})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
