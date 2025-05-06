"""
Definition of TPM 1.2 packets and commands, as additional structures.

All structures are defined as a construct.Struct instance.

A packet is a TPM_PACKET. It can either be a request (RQU) or a response (RSP).

Its `body` is either a `_TPM_RQU_BODY` or `_TPM_RSP_BODY`, identified by its `tag`.

The `body` of a `_TPM_RQU_BODY` is a `_<cmd>_RQU_BODY`, identified by its `ordinal`.

The `body` of a `_TPM_RSP_BODY` is a `_<cmd>_RSP_BODY`, identified by the `lastCommand` in-scope variable at parsing.

`body` fields are not real fields but are exposed to provide easier access and pretty-printing.
"""

# TPM Main Part 3 TPM Commands
# Level 2 Version 1.2, Revision 116
# https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-3-Commands_v1.2_rev116_01032011.pdf

from construct import (
    Byte, Bytes,
    Const,
    Enum,
    FixedSized,
    GreedyRange,
    IfThenElse,
    Int16ub, Int32ub,
    Probe,
    Struct,
    Switch,
    this,
)

from structures import (
    TPM_AUTHDATA,
    TPM_AUTHHANDLE,
    TPM_COMMAND_CODE,
    TPM_DIGEST,
    TPM_KEY_HANDLE,
    TPM_NONCE,
    TPM_PAYLOAD_TYPE,
    TPM_PCR_INFO,
    TPM_PCR_SELECTION,
    TPM_RESULT,
    TPM_SEALED_DATA,
    TPM_SECRET,
    TPM_STORED_DATA,
    TPM_TAG,
)

###################################################################################################
######### Commands' RQU and RSP bodies
###################################################################################################

_TPM_Unseal_RQU_BODY = Struct(
    "parentHandle" / TPM_KEY_HANDLE,
    "inData" / TPM_STORED_DATA,
    "authHandle" / TPM_AUTHHANDLE,
    "nonceOdd" / TPM_NONCE,
    "continueAuthSession" / Byte, # Boolean
    "parentAuth" / TPM_AUTHDATA,
    "dataAuthHandle" / TPM_AUTHHANDLE,
    "datanonceOdd" / TPM_NONCE,
    "continueDataSession" / Byte, # Boolean
    "dataAuth" / TPM_AUTHDATA,
)

_TPM_Unseal_RSP_BODY = Struct(
    "sealedDataSize" / Int32ub,
    "secret" / Bytes(this.sealedDataSize),
    "nonceEven" / TPM_NONCE,
    "continueAuthSession" / Byte, # Boolean
    "resAuth" / TPM_AUTHDATA,
    "dataNonceEven" / TPM_NONCE,
    "continueDataSession" / Byte, # Boolean
    "dataAuth" / TPM_AUTHDATA,
)

###################################################################################################
######### RQU, RSP, TPM_PACKET(S)
###################################################################################################

# hack: global variable + hook to inform of packet size for parsing of unsupported ordinal
#
# TODO: remove once 100% ordinal support is implemented
currentParamSize = None

def param_hook(obj, ctx):
    global currentParamSize

    # breakpoint()

    # paramSize in a packet is the full size of the packet
    # we need the remaining number of bytes in the packet, after
    #     - tag
    #     - paramSize
    #     - ordinal or responseCode
    # n.b. sizeof(TPM_COMMAND_CODE) == sizeof(TPM_RESULT) == 4
    currentParamSize = ctx._.paramSize - TPM_TAG.sizeof() - Int32ub.sizeof() - TPM_RESULT.sizeof()

_TPM_RQU_BODY = Struct(
    "ordinal" / TPM_COMMAND_CODE * param_hook,
    "body" / Switch(this.ordinal,
    {
        TPM_COMMAND_CODE.TPM_Unseal: _TPM_Unseal_RQU_BODY,
        # TODO: Everything else
    },
    default=Bytes(lambda _: currentParamSize),
    )
)

# hack: global variable to inform of last ordinal for RSP parsing
#
# TODO: find a way without polluting global namespace (ugly packet constructor?)
lastCommand = None

_TPM_RSP_BODY = Struct(
    "responseCode" / TPM_RESULT * param_hook,
    "body" / Switch(lambda _: lastCommand, # hack for context-based ordinal inference
    {
        TPM_COMMAND_CODE.TPM_Unseal: _TPM_Unseal_RSP_BODY,
        # TODO: Everything else
    },
    default=Bytes(lambda _: currentParamSize),
    )
)

TPM_PACKET = Struct(
    "tag" / TPM_TAG,
    "paramSize" / Int32ub,
    "body" / IfThenElse(lambda ctx: ctx.tag.startswith('TPM_TAG_RQU'),
        _TPM_RQU_BODY,
        _TPM_RSP_BODY,
    ),
)

def command_hook(obj, ctx):
    global lastCommand

    if obj.tag.startswith('TPM_TAG_RQU'):
        lastCommand = obj.body.ordinal
    else:
        lastCommand = None

TPM_PACKETS = GreedyRange(
    TPM_PACKET * command_hook,
)
