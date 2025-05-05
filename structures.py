"""
Definition of TPM 1.2 structures.

All structures are defined as a construct.Struct instance.


"""

from construct import (
    Byte, Bytes,
    Const,
    Enum,
    FixedSized,
    IfThenElse,
    Int16ub, Int32ub,
    Probe,
    Struct,
    Switch,
    this,
)

# SHA-1 hardcoded in TPM 1.2
digestSize = 20

TPM_AUTHHANDLE = Int32ub
TPM_KEY_HANDLE = Int32ub

TPM_DIGEST = Struct(
    "digest" / Bytes(digestSize),
)

TPM_PCR_SELECTION = Struct(
    "sizeOfSelect" / Int16ub,
    "pcrSelect" / Bytes(this.sizeOfSelect),
)

TPM_PCR_INFO = Struct(
    "pcrSelection" / TPM_PCR_SELECTION,
    "digestAtRelease" / TPM_DIGEST,
    "digestAtCreation" / TPM_DIGEST,
)

TPM_PAYLOAD_TYPE = Enum(Byte,
    TPM_PT_ASYM = 0x01,
    TPM_PT_BIND = 0x02,
    TPM_PT_MIGRATE = 0x03,
    TPM_PT_MAINT = 0x04,
    TPM_PT_SEAL = 0x05,
    TPM_PT_MIGRATE_RESTRICTED = 0x06,
    TPM_PT_MIGRATE_EXTERNAL = 0x07,
    TPM_PT_CMK_MIGRATE = 0x08,

    # TODO: 0x09 – 0x7F : Reserved
    # TODO: 0x80 – 0xFF : Vendor
)

TPM_AUTHDATA = Bytes(digestSize)
TPM_SECRET = TPM_AUTHDATA

TPM_STORED_DATA = Struct(
    "ver" / Const(b'\x01\x01\x00\x00'),
    "sealInfoSize" / Int32ub,
    "sealInfo" / TPM_PCR_INFO,
    "encDataSize" / Int32ub,
    "encData" / Bytes(this.encDataSize),
)

TPM_SEALED_DATA = Struct(
    "payload" / TPM_PAYLOAD_TYPE,
    "authData" / TPM_SECRET,
    "tpmProof" / TPM_SECRET,
    "storedDigest" / TPM_DIGEST,
    "dataSize" / Int32ub,
    "data" / Bytes(this.dataSize),
)

TPM_TAG = Enum(Int16ub,
    TPM_TAG_RQU_COMMAND = 0x00C1,
    TPM_TAG_RQU_AUTH1_COMMAND = 0x00C2,
    TPM_TAG_RQU_AUTH2_COMMAND = 0x00C3,

    TPM_TAG_RSP_COMMAND = 0x00C4,
    TPM_TAG_RSP_AUTH1_COMMAND = 0x00C5,
    TPM_TAG_RSP_AUTH2_COMMAND = 0x00C6,
)

TPM_COMMAND_CODE = Enum(Int32ub,
    # TPM_LoadKey2 = 0x00000041,
    TPM_Unseal = 0x00000018,
    # TODO: everything else
)

TPM_BASE = 0x0
TPM_RESULT = Enum(Int32ub,
    TPM_SUCCESS = TPM_BASE,
    # TODO: everything else
)

TPM_NONCE = Struct(
    "nonce" / Bytes(digestSize),
)

