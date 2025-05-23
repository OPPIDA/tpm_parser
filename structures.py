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
    TPM_ActivateIdentity = 0x0000007A,
    TPM_AuthorizeMigrationKey = 0x0000002B,
    TPM_CertifyKey = 0x00000032,
    TPM_CertifyKey2 = 0x00000033,
    TPM_CertifySelfTest = 0x00000052,
    TPM_ChangeAuth = 0x0000000C,
    TPM_ChangeAuthAsymFinish = 0x0000000F,
    TPM_ChangeAuthAsymStart = 0x0000000E,
    TPM_ChangeAuthOwner = 0x00000010,
    TPM_CMK_ApproveMA = 0x0000001D,
    TPM_CMK_ConvertMigration = 0x00000024,
    TPM_CMK_CreateBlob = 0x0000001B,
    TPM_CMK_CreateKey = 0x00000013,
    TPM_CMK_CreateTicket = 0x00000012,
    TPM_CMK_SetRestrictions = 0x0000001C,
    TPM_ContinueSelfTest = 0x00000053,
    TPM_ConvertMigrationBlob = 0x0000002A,
    TPM_CreateCounter = 0x000000DC,
    TPM_CreateEndorsementKeyPair = 0x00000078,
    TPM_CreateMaintenanceArchive = 0x0000002C,
    TPM_CreateMigrationBlob = 0x00000028,
    TPM_CreateRevocableEK = 0x0000007F,
    TPM_CreateWrapKey = 0x0000001F,
    TPM_DAA_Join = 0x00000029,
    TPM_DAA_Sign = 0x00000031,
    TPM_Delegate_CreateKeyDelegation = 0x000000D4,
    TPM_Delegate_CreateOwnerDelegation = 0x000000D5,
    TPM_Delegate_LoadOwnerDelegation = 0x000000D8,
    TPM_Delegate_Manage = 0x000000D2,
    TPM_Delegate_ReadTable = 0x000000DB,
    TPM_Delegate_UpdateVerification = 0x000000D1,
    TPM_Delegate_VerifyDelegation = 0x000000D6,
    TPM_DirRead = 0x0000001A,
    TPM_DirWriteAuth = 0x00000019,
    TPM_DisableForceClear = 0x0000005E,
    TPM_DisableOwnerClear = 0x0000005C,
    TPM_DisablePubekRead = 0x0000007E,
    TPM_DSAP = 0x00000011,
    TPM_EstablishTransport = 0x000000E6,
    TPM_EvictKey = 0x00000022,
    TPM_ExecuteTransport = 0x000000E7,
    TPM_Extend = 0x00000014,
    TPM_FieldUpgrade = 0x000000AA,
    TPM_FlushSpecific = 0x000000BA,
    TPM_ForceClear = 0x0000005D,
    TPM_GetAuditDigest = 0x00000085,
    TPM_GetAuditDigestSigned = 0x00000086,
    TPM_GetAuditEvent = 0x00000082,
    TPM_GetAuditEventSigned = 0x00000083,
    TPM_GetCapability = 0x00000065,
    TPM_GetCapabilityOwner = 0x00000066,
    TPM_GetCapabilitySigned = 0x00000064,
    TPM_GetOrdinalAuditStatus = 0x0000008C,
    TPM_GetPubKey = 0x00000021,
    TPM_GetRandom = 0x00000046,
    TPM_GetTestResult = 0x00000054,
    TPM_GetTicks = 0x000000F1,
    TPM_IncrementCounter = 0x000000DD,
    TPM_Init = 0x00000097,
    TPM_KeyControlOwner = 0x00000023,
    TPM_KillMaintenanceFeature = 0x0000002E,
    TPM_LoadAuthContext = 0x000000B7,
    TPM_LoadContext = 0x000000B9,
    TPM_LoadKey = 0x00000020,
    TPM_LoadKey2 = 0x00000041,
    TPM_LoadKeyContext = 0x000000B5,
    TPM_LoadMaintenanceArchive = 0x0000002D,
    TPM_LoadManuMaintPub = 0x0000002F,
    TPM_MakeIdentity = 0x00000079,
    TPM_MigrateKey = 0x00000025,
    TPM_NV_DefineSpace = 0x000000CC,
    TPM_NV_ReadValue = 0x000000CF,
    TPM_NV_ReadValueAuth = 0x000000D0,
    TPM_NV_WriteValue = 0x000000CD,
    TPM_NV_WriteValueAuth = 0x000000CE,
    TPM_OIAP = 0x0000000A,
    TPM_OSAP = 0x0000000B,
    TPM_OwnerClear = 0x0000005B,
    TPM_OwnerReadInternalPub = 0x00000081,
    TPM_OwnerReadPubek = 0x0000007D,
    TPM_OwnerSetDisable = 0x0000006E,
    TPM_PCR_Reset = 0x000000C8,
    TPM_PcrRead = 0x00000015,
    TPM_PhysicalDisable = 0x00000070,
    TPM_PhysicalEnable = 0x0000006F,
    TPM_PhysicalSetDeactivated = 0x00000072,
    TPM_Quote = 0x00000016,
    TPM_Quote2 = 0x0000003E,
    TPM_ReadCounter = 0x000000DE,
    TPM_ReadManuMaintPub = 0x00000030,
    TPM_ReadPubek = 0x0000007C,
    TPM_ReleaseCounter = 0x000000DF,
    TPM_ReleaseCounterOwner = 0x000000E0,
    TPM_ReleaseTransportSigned = 0x000000E8,
    TPM_Reset = 0x0000005A,
    TPM_ResetLockValue = 0x00000040,
    TPM_RevokeTrust = 0x00000080,
    TPM_SaveAuthContext = 0x000000B6,
    TPM_SaveContext = 0x000000B8,
    TPM_SaveKeyContext = 0x000000B4,
    TPM_SaveState = 0x00000098,
    TPM_Seal = 0x00000017,
    TPM_Sealx = 0x0000003D,
    TPM_SelfTestFull = 0x00000050,
    TPM_SetCapability = 0x0000003F,
    TPM_SetOperatorAuth = 0x00000074,
    TPM_SetOrdinalAuditStatus = 0x0000008D,
    TPM_SetOwnerInstall = 0x00000071,
    TPM_SetOwnerPointer = 0x00000075,
    TPM_SetRedirection = 0x0000009A,
    TPM_SetTempDeactivated = 0x00000073,
    TPM_SHA1Complete = 0x000000A2,
    TPM_SHA1CompleteExtend = 0x000000A3,
    TPM_SHA1Start = 0x000000A0,
    TPM_SHA1Update = 0x000000A1,
    TPM_Sign = 0x0000003C,
    TPM_Startup = 0x00000099,
    TPM_StirRandom = 0x00000047,
    TPM_TakeOwnership = 0x0000000D,
    TPM_Terminate_Handle = 0x00000096,
    TPM_TickStampBlob = 0x000000F2,
    TPM_UnBind = 0x0000001E,
    TPM_Unseal = 0x00000018,
)

TPM_BASE = 0x0
# TPM_VENDOR_ERROR = TPM_Vendor_Specific32
TPM_NON_FATAL = 0x00000800

TPM_RESULT = Enum(Int32ub,
    TPM_SUCCESS = TPM_BASE,

    TPM_AUTHFAIL = TPM_BASE + 1,
    TPM_BADINDEX = TPM_BASE + 2,
    TPM_BAD_PARAMETER = TPM_BASE + 3,
    TPM_AUDITFAILURE = TPM_BASE + 4,
    TPM_CLEAR_DISABLED = TPM_BASE + 5,
    TPM_DEACTIVATED = TPM_BASE + 6,
    TPM_DISABLED = TPM_BASE + 7,
    TPM_DISABLED_CMD = TPM_BASE + 8,
    TPM_FAIL = TPM_BASE + 9,
    TPM_BAD_ORDINAL = TPM_BASE + 10,
    TPM_INSTALL_DISABLED = TPM_BASE + 11,
    TPM_INVALID_KEYHANDLE = TPM_BASE + 12,
    TPM_KEYNOTFOUND = TPM_BASE + 13,
    TPM_INAPPROPRIATE_ENC = TPM_BASE + 14,
    TPM_MIGRATEFAIL = TPM_BASE + 15,
    TPM_INVALID_PCR_INFO = TPM_BASE + 16,
    TPM_NOSPACE = TPM_BASE + 17,
    TPM_NOSRK = TPM_BASE + 18,
    TPM_NOTSEALED_BLOB = TPM_BASE + 19,
    TPM_OWNER_SET = TPM_BASE + 20,
    TPM_RESOURCES = TPM_BASE + 21,
    TPM_SHORTRANDOM = TPM_BASE + 22,
    TPM_SIZE = TPM_BASE + 23,
    TPM_WRONGPCRVAL = TPM_BASE + 24,
    TPM_BAD_PARAM_SIZE = TPM_BASE + 25,
    TPM_SHA_THREAD = TPM_BASE + 26,
    TPM_SHA_ERROR = TPM_BASE + 27,
    TPM_FAILEDSELFTEST = TPM_BASE + 28,
    TPM_AUTH2FAIL = TPM_BASE + 29,
    TPM_BADTAG = TPM_BASE + 30,
    TPM_IOERROR = TPM_BASE + 31,
    TPM_ENCRYPT_ERROR = TPM_BASE + 32,
    TPM_DECRYPT_ERROR = TPM_BASE + 33,
    TPM_INVALID_AUTHHANDLE = TPM_BASE + 34,
    TPM_NO_ENDORSEMENT = TPM_BASE + 35,
    TPM_INVALID_KEYUSAGE = TPM_BASE + 36,
    TPM_WRONG_ENTITYTYPE = TPM_BASE + 37,
    TPM_INVALID_POSTINIT = TPM_BASE + 38,
    TPM_INAPPROPRIATE_SIG = TPM_BASE + 39,
    TPM_BAD_KEY_PROPERTY = TPM_BASE + 40,
    TPM_BAD_MIGRATION = TPM_BASE + 41,
    TPM_BAD_SCHEME = TPM_BASE + 42,
    TPM_BAD_DATASIZE = TPM_BASE + 43,
    TPM_BAD_MODE = TPM_BASE + 44,
    TPM_BAD_PRESENCE = TPM_BASE + 45,
    TPM_BAD_VERSION = TPM_BASE + 46,
    TPM_NO_WRAP_TRANSPORT = TPM_BASE + 47,
    TPM_AUDITFAIL_UNSUCCESSFUL = TPM_BASE + 48,
    TPM_AUDITFAIL_SUCCESSFUL = TPM_BASE + 49,
    TPM_NOTRESETABLE = TPM_BASE + 50,
    TPM_NOTLOCAL = TPM_BASE + 51,
    TPM_BAD_TYPE = TPM_BASE + 52,
    TPM_INVALID_RESOURCE = TPM_BASE + 53,
    TPM_NOTFIPS = TPM_BASE + 54,
    TPM_INVALID_FAMILY = TPM_BASE + 55,
    TPM_NO_NV_PERMISSION = TPM_BASE + 56,
    TPM_REQUIRES_SIGN = TPM_BASE + 57,
    TPM_KEY_NOTSUPPORTED = TPM_BASE + 58,
    TPM_AUTH_CONFLICT = TPM_BASE + 59,
    TPM_AREA_LOCKED = TPM_BASE + 60,
    TPM_BAD_LOCALITY = TPM_BASE + 61,
    TPM_READ_ONLY = TPM_BASE + 62,
    TPM_PER_NOWRITE = TPM_BASE + 63,
    TPM_FAMILYCOUNT = TPM_BASE + 64,
    TPM_WRITE_LOCKED = TPM_BASE + 65,
    TPM_BAD_ATTRIBUTES = TPM_BASE + 66,
    TPM_INVALID_STRUCTURE = TPM_BASE + 67,
    TPM_KEY_OWNER_CONTROL = TPM_BASE + 68,
    TPM_BAD_COUNTER = TPM_BASE + 69,
    TPM_NOT_FULLWRITE = TPM_BASE + 70,
    TPM_CONTEXT_GAP = TPM_BASE + 71,
    TPM_MAXNVWRITES = TPM_BASE + 72,
    TPM_NOOPERATOR = TPM_BASE + 73,
    TPM_RESOURCEMISSING = TPM_BASE + 74,
    TPM_DELEGATE_LOCK = TPM_BASE + 75,
    TPM_DELEGATE_FAMILY = TPM_BASE + 76,
    TPM_DELEGATE_ADMIN = TPM_BASE + 77,
    TPM_TRANSPORT_NOTEXCLUSIVE = TPM_BASE + 78,
    TPM_OWNER_CONTROL = TPM_BASE + 79,
    TPM_DAA_RESOURCES = TPM_BASE + 80,
    TPM_DAA_INPUT_DATA0 = TPM_BASE + 81,
    TPM_DAA_INPUT_DATA1 = TPM_BASE + 82,
    TPM_DAA_ISSUER_SETTINGS = TPM_BASE + 83,
    TPM_DAA_TPM_SETTINGS = TPM_BASE + 84,
    TPM_DAA_STAGE = TPM_BASE + 85,
    TPM_DAA_ISSUER_VALIDITY = TPM_BASE + 86,
    TPM_DAA_WRONG_W = TPM_BASE + 87,
    TPM_BAD_HANDLE = TPM_BASE + 88,
    TPM_BAD_DELEGATE = TPM_BASE + 89,
    TPM_BADCONTEXT = TPM_BASE + 90,
    TPM_TOOMANYCONTEXTS = TPM_BASE + 91,
    TPM_MA_TICKET_SIGNATURE = TPM_BASE + 92,
    TPM_MA_DESTINATION = TPM_BASE + 93,
    TPM_MA_SOURCE = TPM_BASE + 94,
    TPM_MA_AUTHORITY = TPM_BASE + 95,
    TPM_PERMANENTEK = TPM_BASE + 97,
    TPM_BAD_SIGNATURE = TPM_BASE + 98,
    TPM_NOCONTEXTSPACE = TPM_BASE + 99,

    TPM_RETRY = TPM_BASE + TPM_NON_FATAL,
    TPM_NEEDS_SELFTEST = TPM_BASE + TPM_NON_FATAL + 1,
    TPM_DOING_SELFTEST = TPM_BASE + TPM_NON_FATAL + 2,
    TPM_DEFEND_LOCK_RUNNING = TPM_BASE + TPM_NON_FATAL + 3,
)

TPM_NONCE = Struct(
    "nonce" / Bytes(digestSize),
)

