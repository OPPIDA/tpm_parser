#!/usr/bin/env python

import sys

from command_structures import TPM_PACKETS
from structures import TPM_COMMAND_CODE

# n.b. do not manipulate/clobber the global variables `lastCommand` and `currentParamSize`
# see hacks in command_structures._TPM_RSP_BODY

# TODO:
# Parsing with explicitly raised exceptions, rather than silent stop?
# Yield remaining bytes following successfully parsed packets?
# Parsing with silent exceptions, but skipping to next packet?
# (how? go to next likely-tag? defined invalid/unsupported packet, as default?)

def parse_packets(data: bytes, previous_command: TPM_COMMAND_CODE = None) -> TPM_PACKETS:
    """
    Parse as many packets as possible from a bytestring.

    Silently stops before first invalid packet.

    The packets are assumed to be a sequence of RQU, RSP, RQU, RSP...
    with the RSP corresponding to the RQU immediately before it.

    Should parse without error multiple RQU packets in a row (which don't rely on lastCommand) if last RQU corresponds to next RSP.

    Use previous_command parameter if starting with a RSP packet.
    """
    global lastCommand
    lastCommand = previous_command

    return TPM_PACKETS.parse(data)

def usage():
    print(f"Usage: {sys.argv[0]} <HEX stream of packets> [CMD name]")
    print("Specify CMD name if first packet is a RSP to it.")

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        usage()
        exit(1)

    previous_command = None

    if len(sys.argv) == 3:
        try:
            previous_command = getattr(TPM_COMMAND_CODE, sys.argv[2])
            # actually a variant and not some special attribute like "compile"
            assert previous_command in TPM_COMMAND_CODE.encmapping
        except (AttributeError, AssertionError):
            commands = ', '.join(map(str, TPM_COMMAND_CODE.encmapping.keys()))

            print(f"{sys.argv[2]} is not a valid command.")
            print(f"Valid commands are: {commands}.")
            print()
            usage()
            exit(1)

    data = bytes.fromhex(sys.argv[1])

    print(
        parse_packets(data, previous_command=TPM_COMMAND_CODE.TPM_Unseal)
    )
