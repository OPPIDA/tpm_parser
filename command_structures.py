"""
Definition of TPM 1.2 packets and commands, as additional structures.

All structures are defined as a construct.Struct instance.

A packet is a TPM_PACKET. It can either be a request (RQU) or a response (RSP).

Its `body` is either a `_TPM_RQU_BODY` or `_TPM_RSP_BODY`, identified by its `tag`.

The `body` of a `_TPM_RQU_BODY` is a `_<cmd>_RQU_BODY`, identified by its `ordinal`.

The `body` of a `_TPM_RSP_BODY` is a `_<cmd>_RSP_BODY`, identified by the `lastCommand` in-scope variable at parsing.
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

_TPM_RQU_BODY = Struct(
    "ordinal" / TPM_COMMAND_CODE,
    "body" / Switch(this.ordinal,
    {
        TPM_COMMAND_CODE.TPM_Unseal: _TPM_Unseal_RQU_BODY,
        # TODO: Everything else
    }
    )
)

# hack: global variable to inform of last ordinal for RSP parsing
#
# TODO: find a way without polluting global namespace (ugly packet constructor?)
lastCommand = None

_TPM_RSP_BODY = Struct(
    "responseCode" / TPM_RESULT,
    "body" / Switch(lambda _: lastCommand, # hack for context-based ordinal inference
    {
        TPM_COMMAND_CODE.TPM_Unseal: _TPM_Unseal_RSP_BODY,
        # TODO: Everything else
    }
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

# INTERACTION = Sequence(
#     TPM_PACKET,
#     TPM_PACKET,
# )

