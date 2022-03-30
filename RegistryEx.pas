unit RegistryEx;

{$DEFINE NewFeatures}

interface

uses
  Windows, SysUtils, Classes,
  AuxTypes, AuxClasses;

{===============================================================================
    Library-specific exceptions
===============================================================================}
type
  ERXException = class(Exception);

  ERXTimeConversionError = class(ERXException);
  ERXInvalidValue        = class(ERXException);

  ERXSystemError = class(ERXException);

{===============================================================================
    System constants
===============================================================================}
{-------------------------------------------------------------------------------
    System constants - registry access rights
-------------------------------------------------------------------------------}
const
  KEY_QUERY_VALUE        = $0001;
  KEY_SET_VALUE          = $0002;
  KEY_CREATE_SUB_KEY     = $0004;
  KEY_ENUMERATE_SUB_KEYS = $0008;
  KEY_NOTIFY             = $0010;
  KEY_CREATE_LINK        = $0020;
  KEY_WOW64_32KEY        = $0200;
  KEY_WOW64_64KEY        = $0100;
  KEY_WOW64_RES          = $0300;

  KEY_READ = (STANDARD_RIGHTS_READ or KEY_QUERY_VALUE or KEY_ENUMERATE_SUB_KEYS or KEY_NOTIFY) and not SYNCHRONIZE;

  KEY_WRITE = (STANDARD_RIGHTS_WRITE or KEY_SET_VALUE or KEY_CREATE_SUB_KEY) and not SYNCHRONIZE;

  KEY_EXECUTE = KEY_READ and not SYNCHRONIZE;

  KEY_ALL_ACCESS = (STANDARD_RIGHTS_ALL or KEY_QUERY_VALUE or KEY_SET_VALUE or
                    KEY_CREATE_SUB_KEY or KEY_ENUMERATE_SUB_KEYS or KEY_NOTIFY or
                    KEY_CREATE_LINK) and not SYNCHRONIZE;

{-------------------------------------------------------------------------------
    System constants - open/create options
-------------------------------------------------------------------------------}
const
  REG_OPTION_RESERVED        = DWORD($00000000);  // Parameter is reserved
  REG_OPTION_NON_VOLATILE    = DWORD($00000000);  // Key is preserved when system is rebooted
  REG_OPTION_VOLATILE        = DWORD($00000001);  // Key is not preserved when system is rebooted
  REG_OPTION_CREATE_LINK     = DWORD($00000002);  // Created key is a symbolic link
  REG_OPTION_BACKUP_RESTORE  = DWORD($00000004);  // Open for backup or restore, special access rules, privilege required
  REG_OPTION_OPEN_LINK       = DWORD($00000008);  // Open symbolic link
  REG_OPTION_DONT_VIRTUALIZE = DWORD($00000010);  // Disable Open/Read/Write virtualization for this open and the resulting handle.

  REG_LEGAL_OPTION = REG_OPTION_RESERVED or REG_OPTION_NON_VOLATILE or
                     REG_OPTION_VOLATILE or REG_OPTION_CREATE_LINK or
                     REG_OPTION_BACKUP_RESTORE or REG_OPTION_OPEN_LINK or
                     REG_OPTION_DONT_VIRTUALIZE;

  REG_OPEN_LEGAL_OPTION = REG_OPTION_RESERVED or REG_OPTION_BACKUP_RESTORE or
                          REG_OPTION_OPEN_LINK or REG_OPTION_DONT_VIRTUALIZE;

{-------------------------------------------------------------------------------
    System constants - key creation/open disposition
-------------------------------------------------------------------------------}
const
  REG_CREATED_NEW_KEY     = DWORD($00000001); // New Registry Key created
  REG_OPENED_EXISTING_KEY = DWORD($00000002); // Existing Key opened


{-------------------------------------------------------------------------------
    System constants - hive format to be used by Reg(Nt)SaveKeyEx
-------------------------------------------------------------------------------}
const
  REG_STANDARD_FORMAT = 1;
  REG_LATEST_FORMAT   = 2;
  REG_NO_COMPRESSION  = 4;

{-------------------------------------------------------------------------------
    System constants - key restore & hive load flags
-------------------------------------------------------------------------------}
const
  REG_WHOLE_HIVE_VOLATILE       = DWORD($00000001);           // Restore whole hive volatile
  REG_REFRESH_HIVE              = DWORD($00000002);           // Unwind changes to last flush
  REG_NO_LAZY_FLUSH             = DWORD($00000004);           // Never lazy flush this hive
  REG_FORCE_RESTORE             = DWORD($00000008);           // Force the restore process even when we have open handles on subkeys
  REG_APP_HIVE                  = DWORD($00000010);           // Loads the hive visible to the calling process
  REG_PROCESS_PRIVATE           = DWORD($00000020);           // Hive cannot be mounted by any other process while in use
  REG_START_JOURNAL             = DWORD($00000040);           // Starts Hive Journal
  REG_HIVE_EXACT_FILE_GROWTH    = DWORD($00000080);           // Grow hive file in exact 4k increments
  REG_HIVE_NO_RM                = DWORD($00000100);           // No RM is started for this hive (no transactions)
  REG_HIVE_SINGLE_LOG           = DWORD($00000200);           // Legacy single logging is used for this hive
  REG_BOOT_HIVE                 = DWORD($00000400);           // This hive might be used by the OS loader
  REG_LOAD_HIVE_OPEN_HANDLE     = DWORD($00000800);           // Load the hive and return a handle to its root kcb
  REG_FLUSH_HIVE_FILE_GROWTH    = DWORD($00001000);           // Flush changes to primary hive file size as part of all flushes
  REG_OPEN_READ_ONLY            = DWORD($00002000);           // Open a hive's files in read-only mode
  REG_IMMUTABLE                 = DWORD($00004000);           // Load the hive, but don't allow any modification of it
  REG_NO_IMPERSONATION_FALLBACK = DWORD($00008000);           // Do not fall back to impersonating the caller if hive file access fails
  REG_APP_HIVE_OPEN_READ_ONLY   = DWORD(REG_OPEN_READ_ONLY);  // Open an app hive's files in read-only mode (if the hive was not previously loaded)

{-------------------------------------------------------------------------------
    System constants - unload flags
-------------------------------------------------------------------------------}
const
  REG_FORCE_UNLOAD       = 1;
  REG_UNLOAD_LEGAL_FLAGS = REG_FORCE_UNLOAD;

{-------------------------------------------------------------------------------
    System constants - notify filter values
-------------------------------------------------------------------------------}
const
  REG_NOTIFY_CHANGE_NAME       = DWORD($00000001);  // Create or delete (child)
  REG_NOTIFY_CHANGE_ATTRIBUTES = DWORD($00000002);
  REG_NOTIFY_CHANGE_LAST_SET   = DWORD($00000004);  // time stamp
  REG_NOTIFY_CHANGE_SECURITY   = DWORD($00000008);
  REG_NOTIFY_THREAD_AGNOSTIC   = DWORD($10000000);  // Not associated with a calling thread, can only be used for async user event based notification

  REG_LEGAL_CHANGE_FILTER = REG_NOTIFY_CHANGE_NAME or REG_NOTIFY_CHANGE_ATTRIBUTES or
                            REG_NOTIFY_CHANGE_LAST_SET or REG_NOTIFY_CHANGE_SECURITY or
                            REG_NOTIFY_THREAD_AGNOSTIC;

{-------------------------------------------------------------------------------
    System constants - predefined value types
-------------------------------------------------------------------------------}
const
  REG_NONE                       = 0;   // No value type
  REG_SZ                         = 1;   // Unicode nul terminated string
  REG_EXPAND_SZ                  = 2;   // Unicode nul terminated string (with environment variable references)
  REG_BINARY                     = 3;   // Free form binary
  REG_DWORD                      = 4;   // 32-bit number
  REG_DWORD_LITTLE_ENDIAN        = 4;   // 32-bit number (same as REG_DWORD)
  REG_DWORD_BIG_ENDIAN           = 5;   // 32-bit number
  REG_LINK                       = 6;   // Symbolic Link (unicode)
  REG_MULTI_SZ                   = 7;   // Multiple Unicode strings
  REG_RESOURCE_LIST              = 8;   // Resource list in the resource map
  REG_FULL_RESOURCE_DESCRIPTOR   = 9;   // Resource list in the hardware description
  REG_RESOURCE_REQUIREMENTS_LIST = 10;
  REG_QWORD                      = 11;  // 64-bit number
  REG_QWORD_LITTLE_ENDIAN        = 11;  // 64-bit number (same as REG_QWORD)

{-------------------------------------------------------------------------------
    System constants - (RRF) registry routine flags (for RegGetValue)
-------------------------------------------------------------------------------}
const
  RRF_RT_REG_NONE      = $00000001; // restrict type to REG_NONE      (other data types will not return ERROR_SUCCESS)
  RRF_RT_REG_SZ        = $00000002; // restrict type to REG_SZ        (other data types will not return ERROR_SUCCESS) (automatically converts REG_EXPAND_SZ to REG_SZ unless RRF_NOEXPAND is specified)
  RRF_RT_REG_EXPAND_SZ = $00000004; // restrict type to REG_EXPAND_SZ (other data types will not return ERROR_SUCCESS) (must specify RRF_NOEXPAND or RegGetValue will fail with ERROR_INVALID_PARAMETER)
  RRF_RT_REG_BINARY    = $00000008; // restrict type to REG_BINARY    (other data types will not return ERROR_SUCCESS)
  RRF_RT_REG_DWORD     = $00000010; // restrict type to REG_DWORD     (other data types will not return ERROR_SUCCESS)
  RRF_RT_REG_MULTI_SZ  = $00000020; // restrict type to REG_MULTI_SZ  (other data types will not return ERROR_SUCCESS)
  RRF_RT_REG_QWORD     = $00000040; // restrict type to REG_QWORD     (other data types will not return ERROR_SUCCESS)

  RRF_RT_DWORD         = RRF_RT_REG_BINARY or RRF_RT_REG_DWORD; // restrict type to *32-bit* RRF_RT_REG_BINARY or RRF_RT_REG_DWORD (other data types will not return ERROR_SUCCESS)
  RRF_RT_QWORD         = RRF_RT_REG_BINARY or RRF_RT_REG_QWORD; // restrict type to *64-bit* RRF_RT_REG_BINARY or RRF_RT_REG_DWORD (other data types will not return ERROR_SUCCESS)
  RRF_RT_ANY           = $0000FFFF;                             // no type restriction

  RRF_SUBKEY_WOW6464KEY = $00010000;  // when opening the subkey (if provided) force open from the 64bit location (only one SUBKEY_WOW64* flag can be set or RegGetValue will fail with ERROR_INVALID_PARAMETER)
  RRF_SUBKEY_WOW6432KEY = $00020000;  // when opening the subkey (if provided) force open from the 32bit location (only one SUBKEY_WOW64* flag can be set or RegGetValue will fail with ERROR_INVALID_PARAMETER)
  RRF_WOW64_MASK        = $00030000;

  RRF_NOEXPAND      = $10000000;  // do not automatically expand environment strings if value is of type REG_EXPAND_SZ
  RRF_ZEROONFAILURE = $20000000;  // if pvData is not NULL, set content to all zeros on failure

{-------------------------------------------------------------------------------
    System constants - flags for RegLoadAppKey
-------------------------------------------------------------------------------}
const
  REG_PROCESS_APPKEY               = $00000001;
  REG_USE_CURRENT_SECURITY_CONTEXT = $00000002;

{-------------------------------------------------------------------------------
    System constants - reserved key handles
-------------------------------------------------------------------------------}
const
  HKEY_CLASSES_ROOT                = HKEY($80000000);
  HKEY_CURRENT_USER                = HKEY($80000001);
  HKEY_LOCAL_MACHINE               = HKEY($80000002);
  HKEY_USERS                       = HKEY($80000003);
  HKEY_PERFORMANCE_DATA            = HKEY($80000004);
  HKEY_PERFORMANCE_TEXT            = HKEY($80000050);
  HKEY_PERFORMANCE_NLSTEXT         = HKEY($80000060);
  HKEY_CURRENT_CONFIG              = HKEY($80000005);
  HKEY_DYN_DATA                    = HKEY($80000006);
  HKEY_CURRENT_USER_LOCAL_SETTINGS = HKEY($80000007);

{===============================================================================
--------------------------------------------------------------------------------
                                   TRegistryEx
--------------------------------------------------------------------------------
===============================================================================}
const
  REG_PATH_DELIMITER = '\';

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --
type
  TRXKeyAccessRight = (karQueryValue,karSetValue,karCreateSubKey,
                       karEnumerateSubKeys,karNotify,karCreateLink,
                       karWoW64_32Key,karWoW64_64Key,{standard access rights...}
                       karDelete,karReadControl,karWriteDAC,karWriteOwner,
                       karSynchronize);

  TRXKeyAccessRights = set of TRXKeyAccessRight;

const
  kaWoW64_Res = [karWoW64_32Key,karWoW64_64Key];

  karStandardRead    = [karReadControl];
  karStandardWrite   = [karReadControl];
  karStandardExecute = [karReadControl];
  karStandardAll     = [karDelete,karReadControl,karWriteDAC,karWriteOwner,karSynchronize];

  karRead    = karStandardRead + [karQueryValue,karEnumerateSubKeys,karNotify] - [karSynchronize];
  karWrite   = karStandardWrite + [karSetValue,karCreateSubKey] - [karSynchronize];
  karExecute = karRead - [karSynchronize];

  karAllAccess = karStandardAll + [karQueryValue,karSetValue, karCreateSubKey,
                 karEnumerateSubKeys,karNotify,karCreateLink] - [karSynchronize];

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --
type
  TRXValueType = (vtNone,vtString,vtExpandString,vtBinary,vtDWord,vtDWordLE,
                  vtDWordBE,vtLink,vtMultiString,vtResourceList,
                  vtFullResourceDescriptor,vtResourceRequirementsList,vtQWord,
                  vtQWordLE,vtUnknown);

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --
type
  TRXPredefinedKey = (pkClassesRoot,pkCurrentUser,pkLocalMachine,pkUsers,
                      pkPerformanceData,pkPerformanceText,pkPerformanceNLSText,
                      pkCurrentConfig,pkDynData,pkCurrentUserLocalSettings);

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --
type
  // note that lengths are in unicode characters, without terminating zero
  TRXKeyInfo = record
    SubKeys:            UInt32;
    MaxSubKeyLen:       UInt32;
    MaxClassLen:        UInt32;
    Values:             UInt32;
    MaxValueNameLen:    UInt32;
    MaxValueLen:        UInt32;
    SecurityDescriptor: UInt32;
    LastWriteTime:      TDateTime;
  end;

  TRXValueInfo = record
    ValueType:  TRXValueType;
    DataSize:   TMemSize;
  end;

{===============================================================================
    TRegistryEx - class declaration
===============================================================================}
{$message 'todo: RegNotifyChangeKeyValue'}
type
  TRegistryEx = class(TCustomObject)
  protected
    fAccessRightsSys:   DWORD;
    fAccessRights:      TRXKeyAccessRights;
    fRootKeyHandle:     HKEY;
    fRootKey:           TRXPredefinedKey;
    fCurrentKeyHandle:  HKEY;
    fCurrentKeyName:    String;
    fFlushOnClose:      Boolean;
    // getters, setters
    procedure SetAccessRightsSys(Value: DWORD); virtual;
    procedure SetAccessRights(Value: TRXKeyAccessRights); virtual;
    procedure SetRootKeyHandle(Value: HKEY); virtual;
    procedure SetRootKey(Value: TRXPredefinedKey); virtual;


    //class Function IsRelativeGetRectified(const KeyName: String; out RectifiedKeyName: String): Boolean; virtual;
    //procedure SetCurrentKey(KeyHandle: HKEY; const KeyName: String); virtual;
    //Function GetWorkingKey(Relative: Boolean): HKEY; virtual;
    //Function OpenKeyInternal(const KeyName: String; AccessRights: DWORD): HKEY; overload; virtual;
    //procedure ChangingRootKey; virtual;
    //procedure SetValueData(const ValueName: String; const Data; Size: TMemSize; ValueType: TRXValueType); overload; virtual;
    //procedure SetValueData(const ValueName: String; Data: Integer); overload; virtual;
    //Function GetValueData(const ValueName: String; out Data; Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    //Function GetValueData(const ValueName: String; out Data: Integer): Boolean; overload; virtual;
    procedure Initialize(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights); virtual;
    procedure Finalize; virtual;
  public
    class Function RegistryQuotaAllowed: UInt32; virtual;
    class Function RegistryQuotaUsed: UInt32; virtual;

    constructor Create(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights = karAllAccess); overload;
    constructor Create(AccessRights: TRXKeyAccessRights = karAllAccess); overload;  // root key is set to pkCurrentUser
    destructor Destroy; override;

    ////Function ConnectRegistry(const MachineName: String): Boolean; virtual;
    ////Function DisablePredefinedCache: Boolean; virtual;

    // global key access (does not depend on current key)
    //Function KeyExists(const KeyName: String): Boolean; virtual;
    //Function CreateKey(const KeyName: String): Boolean; virtual;
    //Function DeleteKey(const KeyName: String): Boolean; virtual;

    //Function CopyKey(const SrcKey, DestKey: String): Boolean; virtual;
    //Function MoveKey(const SrcKey, DestKey: String): Boolean; virtual;

    ////Function SaveKey(const Key, FileName: string): Boolean; virtual;
    ////Function LoadKey(const Key, FileName: string): Boolean; virtual;
    ////RegReplaceKey
    ////RegRestoreKey
    ////UnLoadKey


    // current key access
    //Function OpenKey(const KeyName: String; CanCreate: Boolean): Boolean; virtual;
    //Function OpenKeyReadOnly(const KeyName: String): Boolean; virtual;
    //Function GetKeyInfo(out KeyInfo: TRXKeyInfo): Boolean; virtual;
    //procedure GetSubKeys(SubKeys: TStrings); virtual;
    //Function HasSubKeys: Boolean; virtual;
    //procedure FlushKey; virtual;
    procedure CloseKey; virtual; abstract;
    //procedure DeleteSubKeys; virtual;
    //procedure DeleteValues; virtual;
    //procedure DeleteContent; virtual;    

    ////Function DisableReflection: Boolean; virtual;
    ////Function EnableReflection: Boolean; virtual;
    //// RegQueryReflection +^ -> make to property

    ////Function OverridePredefinedKey(RootKey: TRXRootKey): Boolean; virtual;
    //Function RestorePredefinedKey(RootKey: TRXRootKey): Boolean; virtual;
    (*
    Function ValueExists(const ValueName: String): Boolean; virtual;
    procedure GetValues(Values: TStrings); virtual;
    Function GetValueInfo(const ValueName: String; out ValueInfo: TRXValueInfo): Boolean; virtual;
    Function GetValueType(const ValueName: String): TRXValueType; virtual;
    Function GetValueDataSize(const ValueName: String): TMemSize; virtual;
    Function RenameValue(const OldName, NewName: String): Boolean; virtual;
    Function DeleteValue(const ValueName: String): Boolean; virtual;

    // current key values access
    procedure WriteBool(const ValueName: String; Value: Boolean); virtual;
    procedure WriteInt8(const ValueName: String; Value: Int8); virtual;
    procedure WriteUInt8(const ValueName: String; Value: UInt8); virtual;
    procedure WriteInt16(const ValueName: String; Value: Int16); virtual;
    procedure WriteUInt16(const ValueName: String; Value: UInt16); virtual;
    procedure WriteInt32(const ValueName: String; Value: Int32); virtual;
    procedure WriteUInt32(const ValueName: String; Value: UInt32); virtual;
    procedure WriteInt64(const ValueName: String; Value: Int64); virtual;
    procedure WriteUInt64(const ValueName: String; Value: UInt64); virtual;
    procedure WriteInteger(const ValueName: String; Value: Integer); virtual;

    procedure WriteFloat32(const ValueName: String; Value: Float32); virtual;
    procedure WriteFloat64(const ValueName: String; Value: Float64); virtual;
    procedure WriteFloat(const ValueName: String; Value: Double); virtual;
    procedure WriteCurrency(const ValueName: String; Value: Currency); virtual;

    procedure WriteDateTime(const ValueName: String; Value: TDateTime); virtual;
    procedure WriteDate(const ValueName: String; Value: TDateTime); virtual;
    procedure WriteTime(const ValueName: String; Value: TDateTime); virtual;

    procedure WriteString(const ValueName: String; const Value: String); virtual;
    procedure WriteExpandString(const ValueName: String; const Value: String); virtual;
    //procedure WriteStrings(const ValueName: String; Value: TStrings); virtual;

    procedure WriteBinaryBuffer(const ValueName: String; const Buff; Size: TMemSize); virtual;
    procedure WriteBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize); virtual;
    procedure WriteBinaryStream(const ValueName: String; Stream: TStream; Position, Count: Int64); overload; virtual;
    procedure WriteBinaryStream(const ValueName: String; Stream: TStream); overload; virtual;

    Function TryReadBool(const ValueName: String; out Value: Boolean): Boolean; virtual;
    Function TryReadInt8(const ValueName: String; out Value: Int8): Boolean; virtual;
    Function TryReadUInt8(const ValueName: String; out Value: UInt8): Boolean; virtual;
    Function TryReadInt16(const ValueName: String; out Value: Int16): Boolean; virtual;
    Function TryReadUInt16(const ValueName: String; out Value: UInt16): Boolean; virtual;
    Function TryReadInt32(const ValueName: String; out Value: Int32): Boolean; virtual;
    Function TryReadUInt32(const ValueName: String; out Value: UInt32): Boolean; virtual;
    Function TryReadInt64(const ValueName: String; out Value: Int64): Boolean; virtual;
    Function TryReadUInt64(const ValueName: String; out Value: UInt64): Boolean; virtual;
    Function TryReadInteger(const ValueName: String; out Value: Integer): Boolean; virtual;

    Function TryReadFloat32(const ValueName: String; out Value: Float32): Boolean; virtual;
    Function TryReadFloat64(const ValueName: String; out Value: Float64): Boolean; virtual;
    Function TryReadFloat(const ValueName: String; out Value: Double): Boolean; virtual;

    Function TryReadDateTime(const ValueName: String; out Value: TDateTime): Boolean; virtual;
    Function TryReadDate(const ValueName: String; out Value: TDateTime): Boolean; virtual;
    Function TryReadTime(const ValueName: String; out Value: TDateTime): Boolean; virtual;

    Function TryReadString(const ValueName: String; out Value: String): Boolean; virtual;
    //Function TryReadStrings(const ValueName: String; Value: TStrings): Boolean; virtual;

    Function TryReadBinaryBuffer(const ValueName: String; out Buff; var Size: TMemSize): Boolean; virtual;
    Function TryReadBinaryMemory(const ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean; virtual;
    Function TryReadBinaryStream(const ValueName: String; Stream: TStream): Boolean; virtual;

    Function ReadBoolDef(const ValueName: String; Default: Boolean): Boolean; virtual;
    Function ReadInt8Def(const ValueName: String; Default: Int8): Int8; virtual;
    Function ReadUInt8Def(const ValueName: String; Default: UInt8): UInt8; virtual;
    Function ReadInt16Def(const ValueName: String; Default: Int16): Int16; virtual;
    Function ReadUInt16Def(const ValueName: String; Default: UInt16): UInt16; virtual;
    Function ReadInt32Def(const ValueName: String; Default: Int32): Int32; virtual;
    Function ReadUInt32Def(const ValueName: String; Default: UInt32): UInt32; virtual;
    Function ReadInt64Def(const ValueName: String; Default: Int64): Int64; virtual;
    Function ReadUInt64Def(const ValueName: String; Default: UInt64): UInt64; virtual;
    Function ReadIntegerDef(const ValueName: String; Default: Integer): Integer; virtual;

    Function ReadFloat32Def(const ValueName: String; Default: Float32): Float32; virtual;
    Function ReadFloat64Def(const ValueName: String; Default: Float64): Float64; virtual;
    Function ReadFloatDef(const ValueName: String; Default: Double): Double; virtual;

    Function ReadDateTimeDef(const ValueName: String; Default: TDateTime): TDateTime; virtual;
    Function ReadDateDef(const ValueName: String; Default: TDateTime): TDateTime; virtual;
    Function ReadTimeDef(const ValueName: String; Default: TDateTime): TDateTime; virtual;

    Function ReadStringDef(const ValueName: String; const Default: String): String; virtual;

    Function ReadBool(const ValueName: String): Boolean; virtual;
    Function ReadInt8(const ValueName: String): Int8; virtual;
    Function ReadUInt8(const ValueName: String): UInt8; virtual;
    Function ReadInt16(const ValueName: String): Int16; virtual;
    Function ReadUInt16(const ValueName: String): UInt16; virtual;
    Function ReadInt32(const ValueName: String): Int32; virtual;
    Function ReadUInt32(const ValueName: String): UInt32; virtual;
    Function ReadInt64(const ValueName: String): Int64; virtual;
    Function ReadUInt64(const ValueName: String): UInt64; virtual;
    Function ReadInteger(const ValueName: String): Integer; virtual;

    Function ReadFloat32(const ValueName: String): Float32; virtual;
    Function ReadFloat64(const ValueName: String): Float64; virtual;
    Function ReadFloat(const ValueName: String): Double; virtual;

    Function ReadDateTime(const ValueName: String): TDateTime; virtual;
    Function ReadDate(const ValueName: String): TDateTime; virtual;
    Function ReadTime(const ValueName: String): TDateTime; virtual;

    Function ReadString(const ValueName: String): String; virtual;
    //procedure ReadStrings(const ValueName: String; Value: TStrings); virtual;

    Function ReadBinaryBuffer(const ValueName: String; out Buff; Size: TMemSize): TMemSize; virtual;
    Function ReadBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize; virtual;
    Function ReadBinaryStream(const ValueName: String; Stream: TStream): TMemSize; virtual;
   *)
    property AccessRightsSys: DWORD read fAccessRightsSys write SetAccessRightsSys;
    property AccessRights: TRXKeyAccessRights read fAccessRights write SetAccessRights;
    property RootKeyHandle: HKEY read fRootKeyHandle write SetRootKeyHandle;
    property RootKey: TRXPredefinedKey read fRootKey write SetRootKey;
    property CurrentKeyHandle: HKEY read fCurrentKeyHandle;
    property CurrentKeyName: String read fCurrentKeyName;
    property CurrentKeyReflection: Boolean read GetCurrentKeyReflection write SetCurrentKeyReflection;
    property FlushOnClose: Boolean read fFlushOnClose write fFlushOnClose;

  end;

implementation

//type
//  LSTATUS = Int32;
//  LPBYTE  = ^Byte;

//Function SHDeleteKeyW(hkey: HKEY; pszSubKey: LPCWSTR): LSTATUS; stdcall; external 'Shlwapi.dll';
//Function SHCopyKeyW(hkeySrc: HKEY; pszSrcSubKey: LPCWSTR; hkeyDest: HKEY; fReserved: DWORD): LSTATUS; stdcall; external 'Shlwapi.dll';

Function GetSystemRegistryQuota(pdwQuotaAllowed: PDWORD; pdwQuotaUsed: PDWORD): BOOL; stdcall; external 'kernel32.dll';
(*
Function RegEnumValueW(
  hKey:           HKEY;
  dwIndex:        DWORD;
  lpValueName:    LPWSTR;
  lpcchValueName: LPDWORD;
  lpReserved:     LPDWORD;
  lpTyp:          LPDWORD;
  lpData:         LPBYTE;
  lpcbData:       LPDWORD
): LSTATUS; stdcall; external 'Advapi32.dll';
*)
//==============================================================================

Function FileTimeToDateTime(FileTime: TFileTime): TDateTime;
var
  LocalTime:  TFileTime;
  SystemTime: TSystemTime;
begin
If FileTimeToLocalFileTime(FileTime,LocalTime) then
  begin
    If FileTimeToSystemTime(LocalTime,SystemTime) then
      Result := SystemTimeToDateTime(SystemTime)
    else
      raise ERXTimeConversionError.CreateFmt('FileTimeToDateTime: Unable to convert to system time (%d).',[GetLastError]);
  end
else raise ERXTimeConversionError.CreateFmt('FileTimeToDateTime: Unable to convert to local file time (%d).',[GetLastError]);
end;

//------------------------------------------------------------------------------

Function TranslateAccessRights(AccessRights: DWORD): TRXKeyAccessRights; overload;

  procedure SetResultAccessRight(Flag: DWORD; AccessRight: TRXKeyAccessRight);
  begin
    If AccessRights and Flag = Flag then
      Include(Result,AccessRight);
  end;

begin
Result := [];
SetResultAccessRight(KEY_QUERY_VALUE,karQueryValue);
SetResultAccessRight(KEY_SET_VALUE,karSetValue);
SetResultAccessRight(KEY_CREATE_SUB_KEY,karCreateSubKey);
SetResultAccessRight(KEY_ENUMERATE_SUB_KEYS,karEnumerateSubKeys);
SetResultAccessRight(KEY_NOTIFY,karNotify);
SetResultAccessRight(KEY_CREATE_LINK,karCreateLink);
SetResultAccessRight(KEY_WOW64_32KEY,karWoW64_32Key);
SetResultAccessRight(KEY_WOW64_64KEY,karWoW64_64Key);
SetResultAccessRight(_DELETE,karDelete);
SetResultAccessRight(READ_CONTROL,karReadControl);
SetResultAccessRight(WRITE_DAC,karWriteDAC);
SetResultAccessRight(WRITE_OWNER,karWriteOwner);
SetResultAccessRight(SYNCHRONIZE,karSynchronize);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TranslateAccessRights(AccessRights: TRXKeyAccessRights): DWORD; overload;

  procedure SetResultAccessRight(AccessRight: TRXKeyAccessRight; Flag: DWORD);
  begin
    If AccessRight in AccessRights then
      Result := Result or Flag;
  end;

begin
Result := 0;
SetResultAccessRight(karQueryValue,KEY_QUERY_VALUE);
SetResultAccessRight(karSetValue,KEY_SET_VALUE);
SetResultAccessRight(karCreateSubKey,KEY_CREATE_SUB_KEY);
SetResultAccessRight(karEnumerateSubKeys,KEY_ENUMERATE_SUB_KEYS);
SetResultAccessRight(karNotify,KEY_NOTIFY);
SetResultAccessRight(karCreateLink,KEY_CREATE_LINK);
SetResultAccessRight(karWoW64_32Key,KEY_WOW64_32KEY);
SetResultAccessRight(karWoW64_64Key,KEY_WOW64_64KEY);
SetResultAccessRight(karDelete,_DELETE);
SetResultAccessRight(karReadControl,READ_CONTROL);
SetResultAccessRight(karWriteDAC,WRITE_DAC);
SetResultAccessRight(karWriteOwner,WRITE_OWNER);
SetResultAccessRight(karSynchronize,SYNCHRONIZE);
end;

//------------------------------------------------------------------------------

Function TranslateValueType(ValueType: DWORD): TRXValueType; overload;
begin
case ValueType of
  REG_NONE:                       Result := vtNone;
  REG_SZ:                         Result := vtString;
  REG_EXPAND_SZ:                  Result := vtExpandString;
  REG_BINARY:                     Result := vtBinary;
  REG_DWORD:                      Result := vtDWord;
//REG_DWORD_LITTLE_ENDIAN:        Result := vtDWordLE;  // the same as REG_DWORD, duplicit label
  REG_DWORD_BIG_ENDIAN:           Result := vtDWordBE;
  REG_LINK:                       Result := vtLink;
  REG_MULTI_SZ:                   Result := vtMultiString;
  REG_RESOURCE_LIST:              Result := vtResourceList;
  REG_FULL_RESOURCE_DESCRIPTOR:   Result := vtFullResourceDescriptor;
  REG_RESOURCE_REQUIREMENTS_LIST: Result := vtResourceRequirementsList;
  REG_QWORD:                      Result := vtQWord;
//REG_QWORD_LITTLE_ENDIAN:        Result := vtQWordLE;  // the same as REG_QWORD, duplicit label
else
  Result := vtUnknown;
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TranslateValueType(ValueType: TRXValueType): DWORD; overload;
begin
case ValueType of
  vtNone:                     Result := REG_NONE;
  vtString:                   Result := REG_SZ;
  vtExpandString:             Result := REG_EXPAND_SZ;
  vtBinary:                   Result := REG_BINARY;
  vtDWord:                    Result := REG_DWORD;
  vtDWordLE:                  Result := REG_DWORD_LITTLE_ENDIAN;
  vtDWordBE:                  Result := REG_DWORD_BIG_ENDIAN;
  vtLink:                     Result := REG_LINK;
  vtMultiString:              Result := REG_MULTI_SZ;
  vtResourceList:             Result := REG_RESOURCE_LIST;
  vtFullResourceDescriptor:   Result := REG_FULL_RESOURCE_DESCRIPTOR;
  vtResourceRequirementsList: Result := REG_RESOURCE_REQUIREMENTS_LIST;
  vtQWord:                    Result := REG_QWORD;
  vtQWordLE:                  Result := REG_QWORD_LITTLE_ENDIAN;
else
 {rvtUnknown}
  Result := REG_NONE;
end;
end;

//------------------------------------------------------------------------------

Function TranslatePredefinedKey(PredefinedKey: HKEY): TRXPredefinedKey; overload;
begin
case PredefinedKey of
  HKEY_CLASSES_ROOT:                Result := pkClassesRoot;
  HKEY_CURRENT_USER:                Result := pkCurrentUser;
  HKEY_LOCAL_MACHINE:               Result := pkLocalMachine;
  HKEY_USERS:                       Result := pkUsers;
  HKEY_PERFORMANCE_DATA:            Result := pkPerformanceData;
  HKEY_PERFORMANCE_TEXT:            Result := pkPerformanceText;
  HKEY_PERFORMANCE_NLSTEXT:         Result := pkPerformanceNLSText;
  HKEY_CURRENT_CONFIG:              Result := pkCurrentConfig;
  HKEY_DYN_DATA:                    Result := pkDynData;
  HKEY_CURRENT_USER_LOCAL_SETTINGS: Result := pkCurrentUserLocalSettings;
else
  raise ERXInvalidValue.CreateFmt('TranslatePredefinedKey: Invalid key (%d).',[PredefinedKey]);
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TranslatePredefinedKey(PredefinedKey: TRXPredefinedKey): HKEY; overload;
begin
case PredefinedKey of
  pkClassesRoot:              Result := HKEY_CLASSES_ROOT;
  pkCurrentUser:              Result := HKEY_CURRENT_USER;
  pkLocalMachine:             Result := HKEY_LOCAL_MACHINE;
  pkUsers:                    Result := HKEY_USERS;
  pkPerformanceData:          Result := HKEY_PERFORMANCE_DATA;
  pkPerformanceText:          Result := HKEY_PERFORMANCE_TEXT;
  pkPerformanceNLSText:       Result := HKEY_PERFORMANCE_NLSTEXT;
  pkCurrentConfig:            Result := HKEY_CURRENT_CONFIG;
  pkDynData:                  Result := HKEY_DYN_DATA;
  pkCurrentUserLocalSettings: Result := HKEY_CURRENT_USER_LOCAL_SETTINGS;
else
  raise ERXInvalidValue.CreateFmt('TranslatePredefinedKey: Invalid key (%d).',[Ord(PredefinedKey)]);
end;
end;


{===============================================================================
--------------------------------------------------------------------------------
                                   TRegistryEx
--------------------------------------------------------------------------------
===============================================================================}
{===============================================================================
    TRegistryEx - class declaration
===============================================================================}
{-------------------------------------------------------------------------------
    TRegistryEx - protected methods
-------------------------------------------------------------------------------}

procedure TRegistryEx.SetAccessRightsSys(Value: DWORD);
begin
fAccessRightsSys := Value;
fAccessRights := TranslateAccessRights(Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetAccessRights(Value: TRXKeyAccessRights);
begin
fAccessRightsSys := TranslateAccessRights(Value);
fAccessRights := Value;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetRootKeyHandle(Value: HKEY);
begin
CloseKey;
fRootKeyHandle := Value;
fRootKey := TranslatePredefinedKey(Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetRootKey(Value: TRXPredefinedKey);
begin
CloseKey;
fRootKeyHandle := TranslatePredefinedKey(Value);
fRootKey := Value;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.Initialize(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights);
begin
fAccessRightsSys := TranslateAccessRights(AccessRights);;
fAccessRights := AccessRights;
fRootKeyHandle := TranslatePredefinedKey(RootKey);
fRootKey := RootKey;
fCurrentKeyHandle := 0;
fCurrentKeyName := '';
fFlushOnClose := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.Finalize;
begin
CloseKey;
end;

{-------------------------------------------------------------------------------
    TRegistryEx - public methods
-------------------------------------------------------------------------------}

class Function TRegistryEx.RegistryQuotaAllowed: UInt32;
var
  Allowed:  DWORD;
  Used:     DWORD;
begin
If GetSystemRegistryQuota(@Allowed,@Used) then
  Result := UInt32(Allowed)
else
  raise ERXSystemError.CreateFmt('TRegistryEx.RegistryQuotaAllowed: Cannot obtain registry quota (%d).',[GetLastError]);
end;

//------------------------------------------------------------------------------

class Function TRegistryEx.RegistryQuotaUsed: UInt32;
var
  Allowed:  DWORD;
  Used:     DWORD;
begin
If GetSystemRegistryQuota(@Allowed,@Used) then
  Result := UInt32(Used)
else
  raise ERXSystemError.CreateFmt('TRegistryEx.RegistryQuotaAllowed: Cannot obtain registry quota (%d).',[GetLastError]);
end;

//------------------------------------------------------------------------------

constructor TRegistryEx.Create(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights = karAllAccess);
begin
inherited Create;
Initialize(RootKey,AccessRights);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

constructor TRegistryEx.Create(AccessRights: TRXKeyAccessRights = karAllAccess);
begin
Create(pkCurrentUser,AccessRights);
end;

//------------------------------------------------------------------------------

destructor TRegistryEx.Destroy;
begin
Finalize;
inherited;
end;

//==============================================================================
(*
class Function TRegistryEx.IsRelativeGetRectified(const KeyName: String; out RectifiedKeyName: String): Boolean;
begin
RectifiedKeyName := KeyName;
If Length(KeyName) > 0 then
  begin
    Result := KeyName[1] = REG_PATH_DLEIMITER;
    If Result then
      Delete(RectifiedKeyName,1,1);
    If KeyName[Length(KeyName)] = REG_PATH_DLEIMITER then
      Delete(RectifiedKeyName,Length(KeyName),1);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetCurrentKey(KeyHandle: HKEY; const KeyName: String);
begin
If fCurrentKeyHandle <> 0 then
  begin
    CloseKey;
    If Length(fCurrentKeyName) <> 0 then
      fCurrentKeyName := fCurrentKeyName + REG_PATH_DLEIMITER + KeyName
    else
      fCurrentKeyName := KeyName;
  end
else fCurrentKeyName := KeyName;
fCurrentKeyHandle := KeyHandle;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetWorkingKey(Relative: Boolean): HKEY;
begin
If (fCurrentKeyHandle = 0) or not Relative then
  Result := fRootKeyHandle
else
  Result := fCurrentKeyHandle;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.OpenKeyInternal(const KeyName: String; AccessRights: DWORD): HKEY;
var
  TempName: String;
  Relative: Boolean;
begin
Relative := IsRelativeGetRectified(KeyName,TempName);
If RegOpenKeyExW(GetWorkingKey(Relative),PWideChar(StrToWide(TempName)),
  0,AccessRights,Result) <> ERROR_SUCCESS then
  Result := 0;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.ChangingRootKey;
begin
CloseKey;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetValueData(const ValueName: String; const Data; Size: TMemSize; ValueType: TRXValueType);
var
  CallResult: LSTATUS;
begin
CallResult := RegSetValueExW(fCurrentKeyHandle,PWideChar(StrToWide(ValueName)),0,DecodeValueType(ValueType),@Data,DWORD(Size));
If CallResult <> ERROR_SUCCESS then
  raise Exception.CreateFmt('TRegistryEx.SetValue: Unable to write value %s (%d).',[ValueName,CallResult]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.SetValueData(const ValueName: String; Data: Integer);
var
  Temp: DWORD;
begin
Temp := DWORD(Data);
SetValueData(ValueName,Temp,SizeOf(DWORD),rvtDWord);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueData(const ValueName: String; out Data; Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  RegValueType: DWORD;
  RegDataSize:  DWORD;
begin
Result := False;
RegDataSize := DWORD(Size);
If RegQueryValueExW(fCurrentKeyHandle,PWideChar(StrToWide(ValueName)),nil,@RegValueType,@Data,@RegDataSize) = ERROR_SUCCESS then
  Result := (TMemSize(RegDataSize) = Size) and ((DecodeValueType(ValueType) = RegValueType) or
             ((ValueType = rvtString) and (RegValueType in [REG_SZ,REG_EXPAND_SZ])));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueData(const ValueName: String; out Data: Integer): Boolean;
begin
Result := GetValueData(ValueName,Data,SizeOf(Integer),rvtDWord);
end;

//==============================================================================

class Function TRegistryEx.RegistryQuotaAllowed: UInt32;
var
  dwAllowed:  DWORD;
  dwUsed:     DWORD;
begin
If GetSystemRegistryQuota(@dwAllowed,@dwUsed) then
  Result := dwAllowed
else
  raise Exception.CreateFmt('TRegistryEx.RegistryQuotaAllowed: Cannot obtain registry quota (0x%.8x).',[GetLastError]);
end;

//------------------------------------------------------------------------------

class Function TRegistryEx.RegistryQuotaUsed: UInt32;
var
  dwAllowed:  DWORD;
  dwUsed:     DWORD;
begin
If GetSystemRegistryQuota(@dwAllowed,@dwUsed) then
  Result := dwUsed
else
  raise Exception.CreateFmt('TRegistryEx.RegistryQuotaUsed: Cannot obtain registry quota (0x%.8x).',[GetLastError]);
end;

//------------------------------------------------------------------------------

constructor TRegistryEx.Create(AccessRights: TRXKeyAccessRights = karAllAccess);
begin
inherited Create;
SetAccessRights(AccessRights);
SetRootKey(rkCurrentUser);
fCurrentKeyHandle := 0;
fCurrentKeyName := '';;
fFlushOnClose := True;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

constructor TRegistryEx.Create(RootKey: TRXRootKey; AccessRights: TRXKeyAccessRights = karAllAccess);
begin
Create(AccessRights);
SetRootKey(RootKey);
end;

//------------------------------------------------------------------------------

destructor TRegistryEx.Destroy;
begin
CloseKey;
inherited;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.KeyExists(const KeyName: String): Boolean;
var
  TempKey: HKEY;
begin
TempKey := OpenKeyInternal(KeyName,STANDARD_RIGHTS_READ);
try
  Result := TempKey <> 0;
finally
  RegCloseKey(TempKey);
end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CreateKey(const KeyName: String): Boolean;
var
  TempName: String;
  Relative: Boolean;
  TempKey:  HKEY;
begin
Relative := IsRelativeGetRectified(KeyName,TempName);
TempKey := 0;
If RegCreateKeyExW(GetWorkingKey(Relative),PWideChar(StrToWide(TempName)),0,nil,
     REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,nil,TempKey,nil) = ERROR_SUCCESS then
  begin
    RegCloseKey(TempKey);
    Result := True;
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.DeleteKey(const KeyName: String): Boolean;
var
  TempName: String;
  Relative: Boolean;
begin
Relative := IsRelativeGetRectified(KeyName,TempName);
Result := SHDeleteKeyW(GetWorkingKey(Relative),PWideChar(StrToWide(TempName))) = ERROR_SUCCESS;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CopyKey(const SrcKey, DestKey: String): Boolean;
var
  Source:       HKEY;
  Destination:  HKEY;
begin
{$message 'reimplement - do not use SHCopyKeyW, it is recursive and might go into infinite cycle when copying into subnode'}
Result := False;
If KeyExists(SrcKey) and not KeyExists(DestKey) then
  begin
    CreateKey(DestKey);
    Source := OpenKeyInternal(SrcKey,fAccessRightsSys);
    Destination := OpenKeyInternal(DestKey,fAccessRightsSys);
    If Source <> 0 then
    try
      If Destination <> 0 then
      try
        Result := SHCopyKeyW(Source,nil,Destination,0) = ERROR_SUCCESS;
      finally
        RegCloseKey(Destination);
      end;
    finally
      RegCloseKey(Source);
    end;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveKey(const SrcKey, DestKey: String): Boolean;
begin
Result := False;
If CopyKey(SrcKey,DestKey) then
  Result := DeleteKey(SrcKey);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.OpenKey(const KeyName: String; CanCreate: Boolean): Boolean;
var
  TempName: String;
  Relative: Boolean;
  TempKey:  HKEY;
begin
Relative := IsRelativeGetRectified(KeyName,TempName);
If CanCreate then
  Result := RegCreateKeyExW(GetWorkingKey(Relative),PWideChar(StrToWide(TempName)),0,nil,
              REG_OPTION_NON_VOLATILE,fAccessRightsSys,nil,TempKey,nil) = ERROR_SUCCESS
else
  Result := RegOpenKeyExW(GetWorkingKey(Relative),PWideChar(StrToWide(TempName)),
              0,fAccessRightsSys,TempKey) = ERROR_SUCCESS;
If Result then
  SetCurrentKey(TempKey,TempName);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.OpenKeyReadOnly(const KeyName: String): Boolean;
var
  TempName:   String;
  Relative:   Boolean;
  TempKey:    HKEY;
  TempFlags:  DWORD;

  Function TryOpenKeyWithRights(AccessRights: DWORD): Boolean;
  begin
    Result := RegOpenKeyExW(GetWorkingKey(Relative),
                PWideChar(StrToWide(TempName)),
                0,AccessRights,TempKey) = ERROR_SUCCESS;
    If Result then
      OpenKeyReadOnly := True;
  end;

begin
Relative := IsRelativeGetRectified(KeyName,TempName);
TempFlags := fAccessRightsSys and (KEY_WOW64_32KEY or KEY_WOW64_64KEY);
Result := False;
If not TryOpenKeyWithRights(KEY_READ or TempFlags) then
  If not TryOpenKeyWithRights(STANDARD_RIGHTS_READ or KEY_QUERY_VALUE or KEY_ENUMERATE_SUB_KEYS or TempFlags) then
    TryOpenKeyWithRights(KEY_QUERY_VALUE or TempFlags);
If Result then
  SetCurrentKey(TempKey,TempName);            
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetKeyInfo(out KeyInfo: TRXKeyInfo): Boolean;
var
  SubKeys:            DWORD;
  MaxSubKeyLen:       DWORD;
  MaxClassLen:        DWORD;
  Values:             DWORD;
  MaxValueNameLen:    DWORD;
  MaxValueLen:        DWORD;
  SecurityDescriptor: DWORD;
  LastWriteTime:      TFileTime;
begin
FillChar(KeyInfo,SizeOf(TRXKeyInfo),0);
If RegQueryInfoKeyW(fCurrentKeyHandle,nil,nil,nil,@SubKeys,@MaxSubKeyLen,@MaxClassLen,
     @Values,@MaxValueNameLen,@MaxValueLen,@SecurityDescriptor,@LastWriteTime) = ERROR_SUCCESS then
  begin
    KeyInfo.SubKeys            := UInt32(SubKeys);
    KeyInfo.MaxSubKeyLen       := UInt32(MaxSubKeyLen);
    KeyInfo.MaxClassLen        := UInt32(MaxClassLen);
    KeyInfo.Values             := UInt32(Values);
    KeyInfo.MaxValueNameLen    := UInt32(MaxValueNameLen);
    KeyInfo.MaxValueLen        := UInt32(MaxValueLen);
    KeyInfo.SecurityDescriptor := UInt32(SecurityDescriptor);
    KeyInfo.LastWriteTime      := FileTimeToDateTime(LastWriteTime);
    Result := True;
  end
else Result := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetSubKeys(SubKeys: TStrings);
var
  KeyInfo:  TRXKeyInfo;
  i:        Integer;
  TempStr:  WideString;
  Len:      DWORD;
begin
SubKeys.Clear;
If GetKeyInfo(KeyInfo) then
  begin
    SetLength(TempStr,KeyInfo.MaxSubKeyLen + 1);
    i := Pred(Integer(KeyInfo.SubKeys));
    while i >= 0 do
      begin
        Len := Length(TempStr);
        case RegEnumKeyExW(fCurrentKeyHandle,DWORD(i),PWideChar(TempStr),Len,nil,nil,nil,nil) of
          ERROR_SUCCESS:
            SubKeys.Add(WideToStr(Copy(TempStr,1,Len)));
          ERROR_MORE_DATA:
            begin
              SetLength(TempStr,Length(TempStr) * 2);
              Inc(i);
            end;
        else
         {ERROR_NO_MORE_ITEMS}
          i := 0;
        end;
        Dec(i);
      end;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.HasSubKeys: Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
Result := GetKeyInfo(KeyInfo) and (KeyInfo.SubKeys > 0);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.FlushKey;
begin
If fCurrentKeyHandle <> 0 then
  RegFlushKey(fCurrentKeyHandle);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.CloseKey;
begin
If fCurrentKeyHandle <> 0 then
  begin
    If fFlushOnClose then
      FlushKey;
    RegCloseKey(fCurrentKeyHandle);
  end;
fCurrentKeyHandle := 0;
fCurrentKeyName := '';
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ValueExists(const ValueName: String): Boolean;
var
  ValueInfo:  TRXValueInfo;
begin
Result := GetValueInfo(ValueName,ValueInfo);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetValues(Values: TStrings);
var
  KeyInfo:  TRXKeyInfo;
  i:        Integer;
  TempStr:  WideString;
  Len:      DWORD;
begin
Values.Clear;
If GetKeyInfo(KeyInfo) then
  begin
    SetLength(TempStr,KeyInfo.MaxValueNameLen + 1);
    i := Pred(Integer(KeyInfo.Values));
    while i >= 0 do
      begin
        Len := Length(TempStr);
        case RegEnumValueW(fCurrentKeyHandle,DWORD(i),PWideChar(TempStr),@Len,nil,nil,nil,nil) of
          ERROR_SUCCESS:
            Values.Add(WideToStr(Copy(TempStr,1,Len)));
          ERROR_MORE_DATA:
            begin
              SetLength(TempStr,Length(TempStr) * 2);
              Inc(i);
            end;
        else
         {ERROR_NO_MORE_ITEMS}
          i := 0;
        end;
        Dec(i);
      end;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueInfo(const ValueName: String; out ValueInfo: TRXValueInfo): Boolean;
var
  ValueType:  DWORD;
  DataSize:   DWORD;
begin
FillChar(ValueInfo,SizeOf(TRXValueInfo),0);
If RegQueryValueExW(fCurrentKeyHandle,PWideChar(StrToWide(ValueName)),
     nil,@ValueType,nil,@DataSize) = ERROR_SUCCESS then
  begin
    ValueInfo.ValueType := EncodeValueType(ValueType);
    ValueInfo.DataSize := TMemSize(DataSize);
    Result := True;
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueType(const ValueName: String): TRXValueType;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(ValueName,ValueInfo) then
  Result := ValueInfo.ValueType
else
  raise Exception.CreateFmt('TRegistryEx.GetValueType: Cannot obtain value info (0x%.8x).',[GetLastError]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueDataSize(const ValueName: String): TMemSize;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(ValueName,ValueInfo) then
  Result := ValueInfo.DataSize
else
  raise Exception.CreateFmt('TRegistryEx.GetValueDataSize: Cannot obtain value info (0x%.8x).',[GetLastError]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.RenameValue(const OldName, NewName: String): Boolean;
var
  ValueInfo:  TRXValueInfo;
  Buffer:     Pointer;
begin
Result := False;
If ValueExists(OldName) and not ValueExists(NewName) then
  If GetValueInfo(OldName,ValueInfo) then
    If ValueInfo.DataSize > 0 then
      begin
        GetMem(Buffer,ValueInfo.DataSize);
        try
          If GetValueData(OldName,Buffer^,ValueInfo.DataSize,ValueInfo.ValueType) then
            If DeleteValue(OldName) then
              begin
                SetValueData(NewName,Buffer^,ValueInfo.DataSize,ValueInfo.ValueType);
                Result := True;
              end;
        finally
          FreeMem(Buffer,ValueInfo.DataSize);
        end;
      end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.DeleteValue(const ValueName: String): Boolean;
begin
Result := RegDeleteValueW(fCurrentKeyHandle,PWideChar(StrToWide(ValueName))) = ERROR_SUCCESS;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteSubKeys;
var
  SubKeys:  TStringList;
  i:        Integer;
begin
SubKeys := TStringList.Create;
try
  GetSubKeys(SubKeys);
  For i := 0 to Pred(SubKeys.Count) do
    DeleteKey(fCurrentKeyName + REG_PATH_DLEIMITER + SubKeys[i]);
finally
  SubKeys.Free;
end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteValues;
var
  Values: TStringList;
  i:      Integer;
begin
Values := TStringList.Create;
try
  GetValues(Values);
  For i := 0 to Pred(Values.Count) do
    DeleteValue(Values[i]);
finally
  Values.Free;
end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteContent;
begin
DeleteSubKeys;
DeleteValues;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBool(const ValueName: String; Value: Boolean);
begin
SetValueData(ValueName,Ord(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt8(const ValueName: String; Value: Int8);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt8(const ValueName: String; Value: UInt8);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt16(const ValueName: String; Value: Int16);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt16(const ValueName: String; Value: UInt16);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt32(const ValueName: String; Value: Int32);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt32(const ValueName: String; Value: UInt32);
begin
SetValueData(ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt64(const ValueName: String; Value: Int64);
begin
SetValueData(ValueName,Value,SizeOf(Int64),rvtQWord);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt64(const ValueName: String; Value: UInt64);
begin
SetValueData(ValueName,Value,SizeOf(UInt64),rvtQWord);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInteger(const ValueName: String; Value: Integer);
begin
SetValueData(ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat32(const ValueName: String; Value: Float32);
begin
SetValueData(ValueName,Value,SizeOf(Float32),rvtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat64(const ValueName: String; Value: Float64);
begin
SetValueData(ValueName,Value,SizeOf(Float64),rvtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat(const ValueName: String; Value: Double);
begin
WriteFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteDateTime(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteDate(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Int(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteTime(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Frac(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteString(const ValueName: String; const Value: String);
var
  Temp: WideString;
begin
Temp := StrToWide(Value);
SetValueData(ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),rvtString);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteExpandString(const ValueName: String; const Value: String);
var
  Temp: WideString;
begin
Temp := StrToWide(Value);
SetValueData(ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),rvtExpandString);
end;
 
//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryBuffer(const ValueName: String; const Buff; Size: TMemSize);
begin
SetValueData(ValueName,Buff,Size,rvtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize);
begin
SetValueData(ValueName,Memory^,Size,rvtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryStream(const ValueName: String; Stream: TStream; Position, Count: Int64);
var
  Buffer: Pointer;
begin
GetMem(Buffer,TMemSize(Count));
try
  Stream.Seek(Position,soBeginning);
  Stream.ReadBuffer(Buffer^,Count);
  SetValueData(ValueName,Buffer^,TMemSize(Count),rvtBinary);
finally
  FreeMem(Buffer,TMemSize(Count));
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryStream(const ValueName: String; Stream: TStream);
begin
WriteBinaryStream(ValueName,Stream,0,Stream.Size);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBool(const ValueName: String; out Value: Boolean): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := Temp <> 0;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt8(const ValueName: String; out Value: Int8): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := Int8(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt8(const ValueName: String; out Value: UInt8): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := UInt8(Temp);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt16(const ValueName: String; out Value: Int16): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := Int16(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt16(const ValueName: String; out Value: UInt16): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := UInt16(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt32(const ValueName: String; out Value: Int32): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := Int32(Temp);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt32(const ValueName: String; out Value: UInt32): Boolean;
var
  Temp: Integer;
begin
Result := GetValueData(ValueName,Temp);
Value := UInt32(Temp);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt64(const ValueName: String; out Value: Int64): Boolean;
begin
Result := GetValueData(ValueName,Value,SizeOf(Int64),rvtQWord);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt64(const ValueName: String; out Value: UInt64): Boolean;
begin
Result := GetValueData(ValueName,Value,SizeOf(UInt64),rvtQWord);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInteger(const ValueName: String; out Value: Integer): Boolean;
begin
Result := GetValueData(ValueName,Value);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat32(const ValueName: String; out Value: Float32): Boolean;
begin
Result := GetValueData(ValueName,Value,SizeOf(Float32),rvtBinary);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat64(const ValueName: String; out Value: Float64): Boolean;
begin
Result := GetValueData(ValueName,Value,SizeOf(Float64),rvtBinary);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat(const ValueName: String; out Value: Double): Boolean;
begin
Result := TryReadFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadDateTime(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadDate(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
Value := Int(Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadTime(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
Value := Frac(Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadString(const ValueName: String; out Value: String): Boolean;
var
  Size: TMemSize;
  Temp: WideString;
begin
Result := False;
Size := GetValueDataSize(ValueName);
If Size > 0 then
  begin
    SetLength(Temp,Size shr 1);
    If GetValueData(ValueName,PWideChar(Temp)^,Length(Temp) * SizeOf(WideChar),rvtString) then
      begin
        If Temp[Length(Temp)] = #0 then
          SetLength(Temp,Length(Temp) - 1);
        Value := WideToStr(Temp);
        Result := True;
      end;
  end
else
  begin
    Value := '';
    Result := True;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryBuffer(const ValueName: String; out Buff; var Size: TMemSize): Boolean;
var
  DataSize: TMemSize;
begin
Result := False;
DataSize := GetValueDataSize(ValueName);
If DataSize <= Size then
  begin
    If GetValueData(ValueName,Buff,DataSize,rvtBinary) then
      begin
        Size := DataSize;
        Result := True;
      end;
  end
else
  begin
    Size := 0;
    Result := True;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryMemory(const ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean;
begin
Result := TryReadBinaryBuffer(ValueName,Memory^,Size);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryStream(const ValueName: String; Stream: TStream): Boolean;
var
  Buffer:   Pointer;
  DataSize: TMemSize;
begin
Result := False;
DataSize := GetValueDataSize(ValueName);
If DataSize > 0 then
  begin
    GetMem(Buffer,DataSize);
    try
      If GetValueData(ValueName,Buffer^,DataSize,rvtBinary) then
        begin
          Stream.WriteBuffer(Buffer^,DataSize);
          Result := True;
        end;
    finally
      FreeMem(Buffer,DataSize);
    end;
  end
else Result := True;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBoolDef(const ValueName: String; Default: Boolean): Boolean;
begin
If not TryReadBool(ValueName,Result) then
  Result := Default;
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt8Def(const ValueName: String; Default: Int8): Int8;
begin
If not TryReadInt8(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt8Def(const ValueName: String; Default: UInt8): UInt8;
begin
If not TryReadUInt8(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt16Def(const ValueName: String; Default: Int16): Int16;
begin
If not TryReadInt16(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt16Def(const ValueName: String; Default: UInt16): UInt16;
begin
If not TryReadUInt16(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt32Def(const ValueName: String; Default: Int32): Int32;
begin
If not TryReadInt32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt32Def(const ValueName: String; Default: UInt32): UInt32;
begin
If not TryReadUInt32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt64Def(const ValueName: String; Default: Int64): Int64;
begin
If not TryReadInt64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt64Def(const ValueName: String; Default: UInt64): UInt64;
begin
If not TryReadUInt64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadIntegerDef(const ValueName: String; Default: Integer): Integer;
begin
If not TryReadInteger(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat32Def(const ValueName: String; Default: Float32): Float32;
begin
If not TryReadFloat32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat64Def(const ValueName: String; Default: Float64): Float64;
begin
If not TryReadFloat64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloatDef(const ValueName: String; Default: Double): Double;
begin
If not TryReadFloat64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateTimeDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDateTime(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDate(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadTimeDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadTime(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadStringDef(const ValueName: String; const Default: String): String;
begin
If not TryReadString(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBool(const ValueName: String): Boolean;
begin
If not TryReadBool(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadBool: Error reading value %s.',[ValueName]);
end; 

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt8(const ValueName: String): Int8;
begin
If not TryReadInt8(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadInt8: Error reading value %s.',[ValueName]);
end; 

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt8(const ValueName: String): UInt8;
begin
If not TryReadUInt8(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadUInt8: Error reading value %s.',[ValueName]);
end;  

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt16(const ValueName: String): Int16;
begin
If not TryReadInt16(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadInt16: Error reading value %s.',[ValueName]);
end; 

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt16(const ValueName: String): UInt16;
begin
If not TryReadUInt16(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadUInt16: Error reading value %s.',[ValueName]);
end;    

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt32(const ValueName: String): Int32;
begin
If not TryReadInt32(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadInt32: Error reading value %s.',[ValueName]);
end; 

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt32(const ValueName: String): UInt32;
begin
If not TryReadUInt32(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadUInt32: Error reading value %s.',[ValueName]);
end;   

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt64(const ValueName: String): Int64;
begin
If not TryReadInt64(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadInt64: Error reading value %s.',[ValueName]);
end; 

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt64(const ValueName: String): UInt64;
begin
If not TryReadUInt64(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadUInt64: Error reading value %s.',[ValueName]);
end;  

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInteger(const ValueName: String): Integer;
begin
If not TryReadInteger(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadInteger: Error reading value %s.',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat32(const ValueName: String): Float32;
begin
If not TryReadFloat32(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadFloat32: Error reading value %s.',[ValueName]);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat64(const ValueName: String): Float64;
begin
If not TryReadFloat64(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadFloat64: Error reading value %s.',[ValueName]);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat(const ValueName: String): Double;
begin
If not TryReadFloat(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadFloat: Error reading value %s.',[ValueName]);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateTime(const ValueName: String): TDateTime;
begin
If not TryReadDateTime(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadDateTime: Error reading value %s.',[ValueName]);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadDate(const ValueName: String): TDateTime;
begin
If not TryReadDate(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadDate: Error reading value %s.',[ValueName]);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.ReadTime(const ValueName: String): TDateTime;
begin
If not TryReadTime(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadTime: Error reading value %s.',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadString(const ValueName: String): String;
begin
If not TryReadString(ValueName,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadString: Error reading value %s.',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBinaryBuffer(const ValueName: String; out Buff; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryBuffer(ValueName,Buff,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadBinaryBuffer: Error reading value %s.',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryMemory(ValueName,Memory,Result) then
  raise Exception.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value %s.',[ValueName]);
end;

//------------------------------------------------------------------------------
 
Function TRegistryEx.ReadBinaryStream(const ValueName: String; Stream: TStream): TMemSize;
var
  InitPos:  Int64;
begin
InitPos := Stream.Position;
If TryReadBinaryStream(ValueName,Stream) then
  Result := TMemSize(Stream.Position - InitPos)
else
  raise Exception.CreateFmt('TRegistryEx.ReadBinaryStream: Error reading value %s.',[ValueName]);
end;
 *)
end.
