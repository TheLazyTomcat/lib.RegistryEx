unit RegistryEx;

{$IF defined(CPU64) or defined(CPU64BITS)}
  {$DEFINE CPU64bit}
{$ELSEIF defined(CPU16)}
  {$MESSAGE FATAL 'Unsupported CPU.'}
{$ELSE}
  {$DEFINE CPU32bit}
{$IFEND}

{$IF not(defined(MSWINDOWS) or defined(WINDOWS))}
  {$MESSAGE FATAL 'Unsupported operating system.'}
{$IFEND}

{$IFDEF FPC}
  {$MODE ObjFPC}
  {$MODESWITCH DuplicateLocals+}
  {$MODESWITCH PointerToProcVar+}
  {$DEFINE FPC_DisableWarns}
  {$MACRO ON}
{$ENDIF}
{$H+}

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
  ERXInvalidKey          = class(ERXException);
  ERXRegistryWriteError  = class(ERXException);
  ERXRegistryReadError   = class(ERXException);

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
  karWoW64_Res = [karWoW64_32Key,karWoW64_64Key];

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
  TRXKeyCreateOption = (kcoNonVolatile,kcoVolatile,kcoCreateLink,
                        kcoBackupRestore,kcoOpenLink,kcoDontVirtualize);

  TRXKeyCreateOptions = set of TRXKeyCreateOption;

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
{
  Lengths are in unicode characters, without terminating zero, except for
  MaxValueLen, which is in bytes.
}
  TRXKeyInfo = record
    SubKeys:          DWORD;
    MaxSubKeyLen:     DWORD;
    MaxClassLen:      DWORD;
    Values:           DWORD;
    MaxValueNameLen:  DWORD;
    MaxValueLen:      DWORD;
    SecDescrBytes:    DWORD;
    LastWriteTime:    TDateTime;
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
    fAuxOpenResult:     Integer;  // system error code from last call to AuxOpenKey
    //--- getters, setters ---
    procedure SetAccessRightsSys(Value: DWORD); virtual;
    procedure SetAccessRights(Value: TRXKeyAccessRights); virtual;
    procedure SetRootKeyHandle(Value: HKEY); virtual;
    procedure SetRootKey(Value: TRXPredefinedKey); virtual;
    Function GetRootKeyString: String; virtual;
    Function GetCurrentKeyReflection: Boolean; virtual;
    procedure SetCurrentKeyReflection(Value: Boolean); virtual;
    Function GetCurrentKeyPath: String; virtual;
    //--- auxiliaty methods ---
    Function AuxOpenKey(RootKey: HKEY; const KeyName: String; AccessRights: DWORD; out NewKey: HKEY): Boolean; overload; virtual;
    procedure ChangeCurrentKey(KeyHandle: HKEY; const KeyName: String); virtual;
    Function GetWorkingKey(Relative: Boolean; out WorkingKeyName: String): HKEY; overload; virtual;
    Function GetWorkingKey(Relative: Boolean): HKEY; overload; virtual;
    Function GetKeyInfo(Key: HKEY; out KeyInfo: TRXKeyInfo): Boolean; overload; virtual;
    procedure GetSubKeys(Key: HKEY; SubKeys: TStrings); overload; virtual;
    Function GetValueInfo(Key: HKEY; const ValueName: String; out ValueInfo: TRXValueInfo): Boolean; overload; virtual;
    procedure GetValues(Key: HKEY; Values: TStrings); overload; virtual;
    procedure DeleteSubKeys(Key: HKEY); overload; virtual;
    procedure DeleteValues(Key: HKEY); overload; virtual;
    //--- copy/move auxiliaty methods ---
    Function MoveValue(SrcKey: HKEY; const SrcValueName: String; DstKey: HKEY; const DstValueName: String; DeleteSource: Boolean): Boolean; overload; virtual;
    //--- data access methods and macros ---
    procedure SetValueData(Key: HKEY; const ValueName: String; const Data; Size: TMemSize; ValueType: TRXValueType); overload; virtual;
    procedure SetValueData(Key: HKEY; const ValueName: String; Data: Integer); overload; virtual;
    procedure WriteMacro(const TypeName: String; RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value; Size: TMemSize; ValueType: TRXValueType); overload; virtual;
    procedure WriteMacro(const TypeName,KeyName,ValueName: String; const Value; Size: TMemSize; ValueType: TRXValueType); overload; virtual;
    procedure WriteMacro(const TypeName: String; RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Integer); overload; virtual;
    procedure WriteMacro(const TypeName,KeyName,ValueName: String; Value: Integer); overload; virtual;
    Function GetValueDataOut(Key: HKEY; const ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function GetValueDataOut(Key: HKEY; const ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean; overload; virtual;
    Function GetValueDataExtBuff(Key: HKEY; const ValueName: String; out Data; var Size: TMemSize; ValueType: TRXValueType): Boolean; virtual;
    Function GetValueDataStat(Key: HKEY; const ValueName: String; out Data; Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function GetValueDataStat(Key: HKEY; const ValueName: String; out Data: Integer): Boolean; overload; virtual;
    Function TryReadMacroOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacroOut(const KeyName,ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacroOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacroOut(const KeyName,ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacroExtBuff(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value; var Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacroExtBuff(const KeyName,ValueName: String; out Value; var Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacro(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value; Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacro(const KeyName,ValueName: String; out Value; Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function TryReadMacro(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Success: Boolean): Integer; overload; virtual;
    Function TryReadMacro(const KeyName,ValueName: String; out Success: Boolean): Integer; overload; virtual;
    //--- init/final methods ---
    procedure Initialize(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights); virtual;
    procedure Finalize; virtual;
  public
  {
    If functions RegistryQuota* fail to obtain the number, they will return 0.
  }
    class Function RegistryQuotaAllowed: UInt32; virtual;
    class Function RegistryQuotaUsed: UInt32; virtual;
    constructor Create(RootKey: TRXPredefinedKey; AccessRights: TRXKeyAccessRights = karAllAccess); overload;
    constructor Create(AccessRights: TRXKeyAccessRights = karAllAccess); overload;  // root key is set to pkCurrentUser
    destructor Destroy; override;
    //--- global registry functions ---
    ////Function ConnectRegistry(const MachineName: String): Boolean; virtual;
    ////Function DisablePredefinedCache: Boolean; virtual;
  {
    Behavioral classes of TRegistyEx public methods:

      A - parameters RootKey of type TRXPredefinedKey and KeyName string

        These functions operate on a key given by KeyName that is a subkey of
        predefined key given in parameter RootKey.

      B - string parameter KeyName

        If KeyName is relative (ie. does NOT start with path delimiter) and
        current key is open (property CurrentKey[Handle/Name]), then these
        functions operate on a subkey given by parameter KeyName that is within
        current key. Otherwise they operate on a subkey given by KeyName that
        is within predefined key stored in object's property RootKey.

      C - no common parameter

        If current key is open, then these functions operate on the current
        key and its values, otherwise they operate on predefined key stored in
        property RootKey.

      D - no common parameter

        Such functions are affecting only the current key, if any is open.
        If no current key is open, then they have no effect.

    If no class is given, it usually means that the method does not operate on
    any specific key.
    If more than one class is noted, then the method is operating on more than
    one key, and the order of noted classes matches order of parameters.
  }
  {
    OverridePredefinedKey maps specified predefined registry key to another
    open key.

    RestorePredefinedKey restores the default mapping for specified predefined
    registry key.
  }
 {A}Function OverridePredefinedKey(PredefinedKey: TRXPredefinedKey; RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function OverridePredefinedKey(PredefinedKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {D}Function OverridePredefinedKey(PredefinedKey: TRXPredefinedKey): Boolean; overload; virtual;
    Function RestorePredefinedKey(PredefinedKey: TRXPredefinedKey): Boolean; virtual;
    //--- keys management ---
 {A}Function OpenKey(RootKey: TRXPredefinedKey; const KeyName: String; CanCreate: Boolean; out Created: Boolean; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean; overload; virtual;
 {B}Function OpenKey(const KeyName: String; CanCreate: Boolean; out Created: Boolean; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean; overload; virtual;
 {A}Function OpenKey(RootKey: TRXPredefinedKey; const KeyName: String; CanCreate: Boolean): Boolean; overload; virtual;
 {B}Function OpenKey(const KeyName: String; CanCreate: Boolean): Boolean; overload; virtual;
  {
    OpenKeyReadOnly, when successful, will change AccessRight property to
    karRead, but it will also preserve karWoW64_32Key and karWoW64_64Key if
    they were previously set.
  }
 {A}Function OpenKeyReadOnly(RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function OpenKeyReadOnly(const KeyName: String): Boolean; overload; virtual;
  {
    KeyExists tries to open given key for reading. When it succeeds, it is
    assumed the key exists, otherwise it is assumed it does not exist.
  }
 {A}Function KeyExists(RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function KeyExists(const KeyName: String): Boolean; overload; virtual;
 {A}Function CreateKey(RootKey: TRXPredefinedKey; const KeyName: String; AccessRights: TRXKeyAccessRights = karAllAccess; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean; overload; virtual;
 {B}Function CreateKey(const KeyName: String; AccessRights: TRXKeyAccessRights = karAllAccess; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean; overload; virtual;
 {A}Function DeleteKey(RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function DeleteKey(const KeyName: String): Boolean; overload; virtual;
 {D}procedure FlushKey; virtual;
 {D}procedure CloseKey; virtual;
    //--- key information ---
 {A}Function GetKeyInfo(RootKey: TRXPredefinedKey; const KeyName: String; out KeyInfo: TRXKeyInfo): Boolean; overload; virtual;
 {B}Function GetKeyInfo(const KeyName: String; out KeyInfo: TRXKeyInfo): Boolean; overload; virtual;
 {C}Function GetKeyInfo(out KeyInfo: TRXKeyInfo): Boolean; overload; virtual;
 {A}Function HasSubKeys(RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function HasSubKeys(const KeyName: String): Boolean; overload; virtual;
 {C}Function HasSubKeys: Boolean; overload; virtual;
 {A}procedure GetSubKeys(RootKey: TRXPredefinedKey; const KeyName: String; SubKeys: TStrings); overload; virtual;
 {B}procedure GetSubKeys(const KeyName: String; SubKeys: TStrings); overload; virtual;
 {C}procedure GetSubKeys(SubKeys: TStrings); overload; virtual;
    //--- values information/access ---
 {A}Function GetValueInfo(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out ValueInfo: TRXValueInfo): Boolean; overload; virtual;
 {B}Function GetValueInfo(const KeyName,ValueName: String; out ValueInfo: TRXValueInfo): Boolean; overload; virtual;
 {C}Function GetValueInfo(const ValueName: String; out ValueInfo: TRXValueInfo): Boolean; overload; virtual;
 {A}Function HasValues(RootKey: TRXPredefinedKey; const KeyName: String): Boolean; overload; virtual;
 {B}Function HasValues(const KeyName: String): Boolean; overload; virtual;
 {C}Function HasValues: Boolean; overload; virtual;
 {A}procedure GetValues(RootKey: TRXPredefinedKey; const KeyName: String; Values: TStrings); overload; virtual;
 {B}procedure GetValues(const KeyName: String; Values: TStrings); overload; virtual;
 {C}procedure GetValues(Values: TStrings); overload; virtual;
  {
    GetValueType will return vtUnknown in case the value does not exist or
    cannot be queried in general.
  }
 {A}Function GetValueType(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TRXValueType; overload; virtual;
 {B}Function GetValueType(const KeyName,ValueName: String): TRXValueType; overload; virtual;
 {C}Function GetValueType(const ValueName: String): TRXValueType; overload; virtual;
  {
    GetValueDataSize will return 0 in case the value does not exist or cannot
    be queried.
  }
 {A}Function GetValueDataSize(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TMemSize; overload; virtual;
 {B}Function GetValueDataSize(const KeyName,ValueName: String): TMemSize; overload; virtual;
 {C}Function GetValueDataSize(const ValueName: String): TMemSize; overload; virtual;
 {A}Function ValueExists(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean; overload; virtual;
 {B}Function ValueExists(const KeyName,ValueName: String): Boolean; overload; virtual;
 {C}Function ValueExists(const ValueName: String): Boolean; overload; virtual;
 {A}Function DeleteValue(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean; overload; virtual;
 {B}Function DeleteValue(const KeyName,ValueName: String): Boolean; overload; virtual;
 {C}Function DeleteValue(const ValueName: String): Boolean; overload; virtual;
    //--- content deletion ---
 {A}procedure DeleteSubKeys(RootKey: TRXPredefinedKey; const KeyName: String); overload; virtual;
 {B}procedure DeleteSubKeys(const KeyName: String); overload; virtual;
 {C}procedure DeleteSubKeys; overload; virtual;
 {A}procedure DeleteValues(RootKey: TRXPredefinedKey; const KeyName: String); overload; virtual;
 {B}procedure DeleteValues(const KeyName: String); overload; virtual;
 {C}procedure DeleteValues; overload; virtual;
 {A}procedure DeleteContent(RootKey: TRXPredefinedKey; const KeyName: String); overload; virtual;
 {B}procedure DeleteContent(const KeyName: String); overload; virtual;
 {C}procedure DeleteContent; overload; virtual;
    //--- advanced keys and values manipulation ---
    //Function CopyKey(SrcRootKey: TRXPredefinedKey; const SrcKey: String; DestRootKey: TRXPredefinedKey; const DestKey: String): Boolean; overload; virtual;
    Function CopyKey(const SrcKey, DestKey: String): Boolean; overload; virtual;
  {
    Note that MoveKey can be used to effectively rename a key.
  }
    //Function MoveKey(const SrcKey, DestKey: String): Boolean; virtual;
    //Function RenameKey(const OldName, NewName: String): Boolean; virtual;
    {$message 'copy security descr'}
  {
    CopyValue copies value from one arbitrary key into another arbitrary key.
  }
{AA}Function CopyValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{AB}Function CopyValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{BA}Function CopyValue(const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{BB}Function CopyValue(const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
  {
    CopyValueTo copies value from subkey of current key or root key into an
    arbitrary key.
  }
{CA}Function CopyValueTo(const SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{CB}Function CopyValueTo(const SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
  {
    CopyValueFrom copies value from an arbitrary key into a subkey of current
    key or root key.
  }
{AC}Function CopyValueFrom(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean; overload; virtual;  
{BC}Function CopyValueFrom(const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean; overload; virtual;
  {
    CopyValueIn copies value within one key, be it arbitrary, current or root
    key.
  }
 {A}Function CopyValueIn(RootKey: TRXPredefinedKey; const KeyName,SrcValueName,DstValueName: String): Boolean; overload; virtual;
 {B}Function CopyValueIn(const KeyName,SrcValueName,DstValueName: String): Boolean; overload; virtual;
 {C}Function CopyValueIn(const SrcValueName,DstValueName: String): Boolean; overload; virtual;
{AA}Function MoveValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{AB}Function MoveValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{BA}Function MoveValue(const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{BB}Function MoveValue(const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{CA}Function MoveValueTo(const SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{CB}Function MoveValueTo(const SrcValueName: String; const DstKeyName,DstValueName: String): Boolean; overload; virtual;
{AC}Function MoveValueFrom(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean; overload; virtual;
{BC}Function MoveValueFrom(const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean; overload; virtual;
 {A}Function MoveValueIn(RootKey: TRXPredefinedKey; const KeyName,SrcValueName,DstValueName: String): Boolean; overload; virtual;
 {B}Function MoveValueIn(const KeyName,SrcValueName,DstValueName: String): Boolean; overload; virtual;
 {C}Function MoveValueIn(const SrcValueName,DstValueName: String): Boolean; overload; virtual;
  {
    Afaik there is no way to directly rename a value, so it is instead copied
    to a new value with NewName and the original (OldName) is then deleted.
  }
 {A}Function RenameValue(RootKey: TRXPredefinedKey; const KeyName,OldName,NewName: String): Boolean; overload; virtual;
 {B}Function RenameValue(const KeyName,OldName, NewName: String): Boolean; overload; virtual;
 {C}Function RenameValue(const OldName, NewName: String): Boolean; overload; virtual;

    //--- keys saving and loading ---
    ////Function SaveKey(const Key, FileName: string): Boolean; virtual;
    ////Function LoadKey(const Key, FileName: string): Boolean; virtual;
    ////RegReplaceKey
    ////RegRestoreKey
    ////UnLoadKey

    //--- values write ---
  {
    When writing to other key than current or predefined, the key must already
    exist, otherwise an ERXInvalidKey exception is raised.
  }
 {A}procedure WriteBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Boolean); overload; virtual;
 {B}procedure WriteBool(const KeyName,ValueName: String; Value: Boolean); overload; virtual;
 {C}procedure WriteBool(const ValueName: String; Value: Boolean); overload; virtual;
 {A}procedure WriteInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int8); overload; virtual;
 {B}procedure WriteInt8(const KeyName,ValueName: String; Value: Int8); overload; virtual;
 {C}procedure WriteInt8(const ValueName: String; Value: Int8); overload; virtual;
 {A}procedure WriteUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt8); overload; virtual;
 {B}procedure WriteUInt8(const KeyName,ValueName: String; Value: UInt8); overload; virtual;
 {C}procedure WriteUInt8(const ValueName: String; Value: UInt8); overload; virtual;
 {A}procedure WriteInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int16); overload; virtual;
 {B}procedure WriteInt16(const KeyName,ValueName: String; Value: Int16); overload; virtual;
 {C}procedure WriteInt16(const ValueName: String; Value: Int16); overload; virtual;
 {A}procedure WriteUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt16); overload; virtual;
 {B}procedure WriteUInt16(const KeyName,ValueName: String; Value: UInt16); overload; virtual;
 {C}procedure WriteUInt16(const ValueName: String; Value: UInt16); overload; virtual;
 {A}procedure WriteInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int32); overload; virtual;
 {B}procedure WriteInt32(const KeyName,ValueName: String; Value: Int32); overload; virtual;
 {C}procedure WriteInt32(const ValueName: String; Value: Int32); overload; virtual;
 {A}procedure WriteUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt32); overload; virtual;
 {B}procedure WriteUInt32(const KeyName,ValueName: String; Value: UInt32); overload; virtual;
 {C}procedure WriteUInt32(const ValueName: String; Value: UInt32); overload; virtual;
 {A}procedure WriteInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int64); overload; virtual;
 {B}procedure WriteInt64(const KeyName,ValueName: String; Value: Int64); overload; virtual;
 {C}procedure WriteInt64(const ValueName: String; Value: Int64); overload; virtual;
 {A}procedure WriteUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt64); overload; virtual;
 {B}procedure WriteUInt64(const KeyName,ValueName: String; Value: UInt64); overload; virtual;
 {C}procedure WriteUInt64(const ValueName: String; Value: UInt64); overload; virtual;
 {A}procedure WriteInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Integer); overload; virtual;
 {B}procedure WriteInteger(const KeyName,ValueName: String; Value: Integer); overload; virtual;
 {C}procedure WriteInteger(const ValueName: String; Value: Integer); overload; virtual;
 {A}procedure WriteFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Float32); overload; virtual;
 {B}procedure WriteFloat32(const KeyName,ValueName: String; Value: Float32); overload; virtual;
 {C}procedure WriteFloat32(const ValueName: String; Value: Float32); overload; virtual;
 {A}procedure WriteFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Float64); overload; virtual;
 {B}procedure WriteFloat64(const KeyName,ValueName: String; Value: Float64); overload; virtual;
 {C}procedure WriteFloat64(const ValueName: String; Value: Float64); overload; virtual;
 {A}procedure WriteFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Double); overload; virtual;
 {B}procedure WriteFloat(const KeyName,ValueName: String; Value: Double); overload; virtual;
 {C}procedure WriteFloat(const ValueName: String; Value: Double); overload; virtual;
 {A}procedure WriteCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Currency); overload; virtual;
 {B}procedure WriteCurrency(const KeyName,ValueName: String; Value: Currency); overload; virtual;
 {C}procedure WriteCurrency(const ValueName: String; Value: Currency); overload; virtual;
 {A}procedure WriteDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {B}procedure WriteDateTime(const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {C}procedure WriteDateTime(const ValueName: String; Value: TDateTime); overload; virtual;
 {A}procedure WriteDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {B}procedure WriteDate(const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {C}procedure WriteDate(const ValueName: String; Value: TDateTime); overload; virtual;
 {A}procedure WriteTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {B}procedure WriteTime(const KeyName,ValueName: String; Value: TDateTime); overload; virtual;
 {C}procedure WriteTime(const ValueName: String; Value: TDateTime); overload; virtual;
 {A}procedure WriteString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value: String); overload; virtual;
 {B}procedure WriteString(const KeyName,ValueName: String; const Value: String); overload; virtual;
 {C}procedure WriteString(const ValueName: String; const Value: String); overload; virtual;
 {A}procedure WriteExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value: String; UnExpand: Boolean = False); overload; virtual;
 {B}procedure WriteExpandString(const KeyName,ValueName: String; const Value: String; UnExpand: Boolean = False); overload; virtual;
 {C}procedure WriteExpandString(const ValueName: String; const Value: String; UnExpand: Boolean = False); overload; virtual;
 {A}procedure WriteMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings); overload; virtual;
 {B}procedure WriteMultiString(const KeyName,ValueName: String; Value: TStrings); overload; virtual;
 {C}procedure WriteMultiString(const ValueName: String; Value: TStrings); overload; virtual;
 {A}procedure WriteBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Buff; Size: TMemSize); overload; virtual;
 {B}procedure WriteBinaryBuffer(const KeyName,ValueName: String; const Buff; Size: TMemSize); overload; virtual;
 {C}procedure WriteBinaryBuffer(const ValueName: String; const Buff; Size: TMemSize); overload; virtual;
 {A}procedure WriteBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize); overload; virtual;
 {B}procedure WriteBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize); overload; virtual;
 {C}procedure WriteBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize); overload; virtual;
  {
    Position of the passed stream is undefined after the call, do not assume
    anything about its value.
  }
 {A}procedure WriteBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream; Position, Count: Int64); overload; virtual;
 {B}procedure WriteBinaryStream(const KeyName,ValueName: String; Stream: TStream; Position, Count: Int64); overload; virtual;
 {C}procedure WriteBinaryStream(const ValueName: String; Stream: TStream; Position, Count: Int64); overload; virtual;
 {A}procedure WriteBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream); overload; virtual;
 {B}procedure WriteBinaryStream(const KeyName,ValueName: String; Stream: TStream); overload; virtual;
 {C}procedure WriteBinaryStream(const ValueName: String; Stream: TStream); overload; virtual;
    //--- values try-read ---
 {A}Function TryReadBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Boolean): Boolean; overload; virtual;
 {B}Function TryReadBool(const KeyName,ValueName: String; out Value: Boolean): Boolean; overload; virtual;
 {C}Function TryReadBool(const ValueName: String; out Value: Boolean): Boolean; overload; virtual;
 {A}Function TryReadInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int8): Boolean; overload; virtual;
 {B}Function TryReadInt8(const KeyName,ValueName: String; out Value: Int8): Boolean; overload; virtual;
 {C}Function TryReadInt8(const ValueName: String; out Value: Int8): Boolean; overload; virtual;
 {A}Function TryReadUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt8): Boolean; overload; virtual;
 {B}Function TryReadUInt8(const KeyName,ValueName: String; out Value: UInt8): Boolean; overload; virtual;
 {C}Function TryReadUInt8(const ValueName: String; out Value: UInt8): Boolean; overload; virtual;
 {A}Function TryReadInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int16): Boolean; overload; virtual;
 {B}Function TryReadInt16(const KeyName,ValueName: String; out Value: Int16): Boolean; overload; virtual;
 {C}Function TryReadInt16(const ValueName: String; out Value: Int16): Boolean; overload; virtual;
 {A}Function TryReadUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt16): Boolean; overload; virtual;
 {B}Function TryReadUInt16(const KeyName,ValueName: String; out Value: UInt16): Boolean; overload; virtual;
 {C}Function TryReadUInt16(const ValueName: String; out Value: UInt16): Boolean; overload; virtual;
 {A}Function TryReadInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int32): Boolean; overload; virtual;
 {B}Function TryReadInt32(const KeyName,ValueName: String; out Value: Int32): Boolean; overload; virtual;
 {C}Function TryReadInt32(const ValueName: String; out Value: Int32): Boolean; overload; virtual;
 {A}Function TryReadUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt32): Boolean; overload; virtual;
 {B}Function TryReadUInt32(const KeyName,ValueName: String; out Value: UInt32): Boolean; overload; virtual;
 {C}Function TryReadUInt32(const ValueName: String; out Value: UInt32): Boolean; overload; virtual;
 {A}Function TryReadInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int64): Boolean; overload; virtual;
 {B}Function TryReadInt64(const KeyName,ValueName: String; out Value: Int64): Boolean; overload; virtual;
 {C}Function TryReadInt64(const ValueName: String; out Value: Int64): Boolean; overload; virtual;
 {A}Function TryReadUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt64): Boolean; overload; virtual;
 {B}Function TryReadUInt64(const KeyName,ValueName: String; out Value: UInt64): Boolean; overload; virtual;
 {C}Function TryReadUInt64(const ValueName: String; out Value: UInt64): Boolean; overload; virtual;
 {A}Function TryReadInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Integer): Boolean; overload; virtual;
 {B}Function TryReadInteger(const KeyName,ValueName: String; out Value: Integer): Boolean; overload; virtual;
 {C}Function TryReadInteger(const ValueName: String; out Value: Integer): Boolean; overload; virtual;
 {A}Function TryReadFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Float32): Boolean; overload; virtual;
 {B}Function TryReadFloat32(const KeyName,ValueName: String; out Value: Float32): Boolean; overload; virtual;
 {C}Function TryReadFloat32(const ValueName: String; out Value: Float32): Boolean; overload; virtual;
 {A}Function TryReadFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Float64): Boolean; overload; virtual;
 {B}Function TryReadFloat64(const KeyName,ValueName: String; out Value: Float64): Boolean; overload; virtual;
 {C}Function TryReadFloat64(const ValueName: String; out Value: Float64): Boolean; overload; virtual;
 {A}Function TryReadFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Double): Boolean; overload; virtual;
 {B}Function TryReadFloat(const KeyName,ValueName: String; out Value: Double): Boolean; overload; virtual;
 {C}Function TryReadFloat(const ValueName: String; out Value: Double): Boolean; overload; virtual;
 {A}Function TryReadCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Currency): Boolean; overload; virtual;
 {B}Function TryReadCurrency(const KeyName,ValueName: String; out Value: Currency): Boolean; overload; virtual;
 {C}Function TryReadCurrency(const ValueName: String; out Value: Currency): Boolean; overload; virtual;
 {A}Function TryReadDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {B}Function TryReadDateTime(const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {C}Function TryReadDateTime(const ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {A}Function TryReadDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {B}Function TryReadDate(const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {C}Function TryReadDate(const ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {A}Function TryReadTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {B}Function TryReadTime(const KeyName,ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {C}Function TryReadTime(const ValueName: String; out Value: TDateTime): Boolean; overload; virtual;
 {A}Function TryReadString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: String): Boolean; overload; virtual;
 {B}Function TryReadString(const KeyName,ValueName: String; out Value: String): Boolean; overload; virtual;
 {C}Function TryReadString(const ValueName: String; out Value: String): Boolean; overload; virtual;
 {A}Function TryReadExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: String; Expand: Boolean = False): Boolean; overload; virtual;
 {B}Function TryReadExpandString(const KeyName,ValueName: String; out Value: String; Expand: Boolean = False): Boolean; overload; virtual;
 {C}Function TryReadExpandString(const ValueName: String; out Value: String; Expand: Boolean = False): Boolean; overload; virtual;
 {A}Function TryReadMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings): Boolean; overload; virtual;
 {B}Function TryReadMultiString(const KeyName,ValueName: String; Value: TStrings): Boolean; overload; virtual;
 {C}Function TryReadMultiString(const ValueName: String; Value: TStrings): Boolean; overload; virtual;
  {
    Size must, on enter, contain size of the preallocated output buffer.
    In case of success, it will contain true amount of data stored into the
    buffer. In case of failure its value is undefined and content of Buff is
    also undefined (might be changed).

    To obtain size of buffer that is required to store the data, use method
    GetValueDataSize.
  }
 {A}Function TryReadBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Buff; var Size: TMemSize): Boolean; overload; virtual;
 {B}Function TryReadBinaryBuffer(const KeyName,ValueName: String; out Buff; var Size: TMemSize): Boolean; overload; virtual;
 {C}Function TryReadBinaryBuffer(const ValueName: String; out Buff; var Size: TMemSize): Boolean; overload; virtual;
  {
    TryReadBinaryMemory behaves the same as TryReadBinaryBuffer.
  }
 {A}Function TryReadBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean; overload; virtual;
 {B}Function TryReadBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean; overload; virtual;
 {C}Function TryReadBinaryMemory(const ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean; overload; virtual;
  {
    This funtion does not need preallocated buffer. Instead, it itself
    allocates memory space that is necessary to store the data and, when it
    succeeds, returns pointer to this memory along with size of the allocated
    space. If it fails, the content of output arguments Memory and Size is
    undefined (no memory is left allocated, so there is no leak).

    To free the allocated memory, use standard memory management functions
    (FreeMem, ReallocMem, ...).

    This function is intended for situations where amount of stored data can
    rapidly change (eg. values in HKEY_PERFORMANCE_DATA).
  }
 {A}Function TryReadBinaryMemoryOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean; overload; virtual;
 {B}Function TryReadBinaryMemoryOut(const KeyName,ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean; overload; virtual;
 {C}Function TryReadBinaryMemoryOut(const ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean; overload; virtual;
  {
    Position of the stream is undefined after the call.
  }
 {A}Function TryReadBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream): Boolean; overload; virtual;
 {B}Function TryReadBinaryStream(const KeyName,ValueName: String; Stream: TStream): Boolean; overload; virtual;
 {C}Function TryReadBinaryStream(const ValueName: String; Stream: TStream): Boolean; overload; virtual;
    //--- values read-def ---
 {A}Function ReadBoolDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Boolean): Boolean; overload; virtual;
 {B}Function ReadBoolDef(const KeyName,ValueName: String; Default: Boolean): Boolean; overload; virtual;
 {C}Function ReadBoolDef(const ValueName: String; Default: Boolean): Boolean; overload; virtual;
 {A}Function ReadInt8Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int8): Int8; overload; virtual;
 {B}Function ReadInt8Def(const KeyName,ValueName: String; Default: Int8): Int8; overload; virtual;
 {C}Function ReadInt8Def(const ValueName: String; Default: Int8): Int8; overload; virtual;
 {A}Function ReadUInt8Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt8): UInt8; overload; virtual;
 {B}Function ReadUInt8Def(const KeyName,ValueName: String; Default: UInt8): UInt8; overload; virtual;
 {C}Function ReadUInt8Def(const ValueName: String; Default: UInt8): UInt8; overload; virtual;
 {A}Function ReadInt16Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int16): Int16; overload; virtual;
 {B}Function ReadInt16Def(const KeyName,ValueName: String; Default: Int16): Int16; overload; virtual;
 {C}Function ReadInt16Def(const ValueName: String; Default: Int16): Int16; overload; virtual;
 {A}Function ReadUInt16Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt16): UInt16; overload; virtual;
 {B}Function ReadUInt16Def(const KeyName,ValueName: String; Default: UInt16): UInt16; overload; virtual;
 {C}Function ReadUInt16Def(const ValueName: String; Default: UInt16): UInt16; overload; virtual;
 {A}Function ReadInt32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int32): Int32; overload; virtual;
 {B}Function ReadInt32Def(const KeyName,ValueName: String; Default: Int32): Int32; overload; virtual;
 {C}Function ReadInt32Def(const ValueName: String; Default: Int32): Int32; overload; virtual;
 {A}Function ReadUInt32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt32): UInt32; overload; virtual;
 {B}Function ReadUInt32Def(const KeyName,ValueName: String; Default: UInt32): UInt32; overload; virtual;
 {C}Function ReadUInt32Def(const ValueName: String; Default: UInt32): UInt32; overload; virtual;
 {A}Function ReadInt64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int64): Int64; overload; virtual;
 {B}Function ReadInt64Def(const KeyName,ValueName: String; Default: Int64): Int64; overload; virtual;
 {C}Function ReadInt64Def(const ValueName: String; Default: Int64): Int64; overload; virtual;
 {A}Function ReadUInt64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt64): UInt64; overload; virtual;
 {B}Function ReadUInt64Def(const KeyName,ValueName: String; Default: UInt64): UInt64; overload; virtual;
 {C}Function ReadUInt64Def(const ValueName: String; Default: UInt64): UInt64; overload; virtual;
 {A}Function ReadIntegerDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Integer): Integer; overload; virtual;
 {B}Function ReadIntegerDef(const KeyName,ValueName: String; Default: Integer): Integer; overload; virtual;
 {C}Function ReadIntegerDef(const ValueName: String; Default: Integer): Integer; overload; virtual;
 {A}Function ReadFloat32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Float32): Float32; overload; virtual;
 {B}Function ReadFloat32Def(const KeyName,ValueName: String; Default: Float32): Float32; overload; virtual;
 {C}Function ReadFloat32Def(const ValueName: String; Default: Float32): Float32; overload; virtual;
 {A}Function ReadFloat64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Float64): Float64; overload; virtual;
 {B}Function ReadFloat64Def(const KeyName,ValueName: String; Default: Float64): Float64; overload; virtual;
 {C}Function ReadFloat64Def(const ValueName: String; Default: Float64): Float64; overload; virtual;
 {A}Function ReadFloatDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Double): Double; overload; virtual;
 {B}Function ReadFloatDef(const KeyName,ValueName: String; Default: Double): Double; overload; virtual;
 {C}Function ReadFloatDef(const ValueName: String; Default: Double): Double; overload; virtual;
 {A}Function ReadCurrencyDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Currency): Currency; overload; virtual;
 {B}Function ReadCurrencyDef(const KeyName,ValueName: String; Default: Currency): Currency; overload; virtual;
 {C}Function ReadCurrencyDef(const ValueName: String; Default: Currency): Currency; overload; virtual;
 {A}Function ReadDateTimeDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {B}Function ReadDateTimeDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {C}Function ReadDateTimeDef(const ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {A}Function ReadDateDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {B}Function ReadDateDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {C}Function ReadDateDef(const ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {A}Function ReadTimeDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {B}Function ReadTimeDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {C}Function ReadTimeDef(const ValueName: String; Default: TDateTime): TDateTime; overload; virtual;
 {A}Function ReadStringDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Default: String): String; overload; virtual;
 {B}Function ReadStringDef(const KeyName,ValueName: String; const Default: String): String; overload; virtual;
 {C}Function ReadStringDef(const ValueName: String; const Default: String): String; overload; virtual;
 {A}Function ReadExpandStringDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Default: String; Expand: Boolean = False): String; overload; virtual;
 {B}Function ReadExpandStringDef(const KeyName,ValueName: String; const Default: String; Expand: Boolean = False): String; overload; virtual;
 {C}Function ReadExpandStringDef(const ValueName: String; const Default: String; Expand: Boolean = False): String; overload; virtual;
    //--- values read ---
    {$message 'different exception for invalid key'}  
 {A}Function ReadBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean; overload; virtual;
 {B}Function ReadBool(const KeyName,ValueName: String): Boolean; overload; virtual;
 {C}Function ReadBool(const ValueName: String): Boolean; overload; virtual;
 {A}Function ReadInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int8; overload; virtual;
 {B}Function ReadInt8(const KeyName,ValueName: String): Int8; overload; virtual;
 {C}Function ReadInt8(const ValueName: String): Int8; overload; virtual;
 {A}Function ReadUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt8; overload; virtual;
 {B}Function ReadUInt8(const KeyName,ValueName: String): UInt8; overload; virtual;
 {C}Function ReadUInt8(const ValueName: String): UInt8; overload; virtual;
 {A}Function ReadInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int16; overload; virtual;
 {B}Function ReadInt16(const KeyName,ValueName: String): Int16; overload; virtual;
 {C}Function ReadInt16(const ValueName: String): Int16; overload; virtual;
 {A}Function ReadUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt16; overload; virtual;
 {B}Function ReadUInt16(const KeyName,ValueName: String): UInt16; overload; virtual;
 {C}Function ReadUInt16(const ValueName: String): UInt16; overload; virtual;
 {A}Function ReadInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int32; overload; virtual;
 {B}Function ReadInt32(const KeyName,ValueName: String): Int32; overload; virtual;
 {C}Function ReadInt32(const ValueName: String): Int32; overload; virtual;
 {A}Function ReadUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt32; overload; virtual;
 {B}Function ReadUInt32(const KeyName,ValueName: String): UInt32; overload; virtual;
 {C}Function ReadUInt32(const ValueName: String): UInt32; overload; virtual;
 {A}Function ReadInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int64; overload; virtual;
 {B}Function ReadInt64(const KeyName,ValueName: String): Int64; overload; virtual;
 {C}Function ReadInt64(const ValueName: String): Int64; overload; virtual;
 {A}Function ReadUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt64; overload; virtual;
 {B}Function ReadUInt64(const KeyName,ValueName: String): UInt64; overload; virtual;
 {C}Function ReadUInt64(const ValueName: String): UInt64; overload; virtual;
 {A}Function ReadInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Integer; overload; virtual;
 {B}Function ReadInteger(const KeyName,ValueName: String): Integer; overload; virtual;
 {C}Function ReadInteger(const ValueName: String): Integer; overload; virtual;
 {A}Function ReadFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Float32; overload; virtual;
 {B}Function ReadFloat32(const KeyName,ValueName: String): Float32; overload; virtual;
 {C}Function ReadFloat32(const ValueName: String): Float32; overload; virtual;
 {A}Function ReadFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Float64; overload; virtual;
 {B}Function ReadFloat64(const KeyName,ValueName: String): Float64; overload; virtual;
 {C}Function ReadFloat64(const ValueName: String): Float64; overload; virtual;
 {A}Function ReadFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Double; overload; virtual;
 {B}Function ReadFloat(const KeyName,ValueName: String): Double; overload; virtual;
 {C}Function ReadFloat(const ValueName: String): Double; overload; virtual;
 {A}Function ReadCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Currency; overload; virtual;
 {B}Function ReadCurrency(const KeyName,ValueName: String): Currency; overload; virtual;
 {C}Function ReadCurrency(const ValueName: String): Currency; overload; virtual;
 {A}Function ReadDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime; overload; virtual;
 {B}Function ReadDateTime(const KeyName,ValueName: String): TDateTime; overload; virtual;
 {C}Function ReadDateTime(const ValueName: String): TDateTime; overload; virtual;
 {A}Function ReadDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime; overload; virtual;
 {B}Function ReadDate(const KeyName,ValueName: String): TDateTime; overload; virtual;
 {C}Function ReadDate(const ValueName: String): TDateTime; overload; virtual;
 {A}Function ReadTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime; overload; virtual;
 {B}Function ReadTime(const KeyName,ValueName: String): TDateTime; overload; virtual;
 {C}Function ReadTime(const ValueName: String): TDateTime; overload; virtual;
 {A}Function ReadString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): String; overload; virtual;
 {B}Function ReadString(const KeyName,ValueName: String): String; overload; virtual;
 {C}Function ReadString(const ValueName: String): String; overload; virtual;
 {A}Function ReadExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Expand: Boolean = False): String; overload; virtual;
 {B}Function ReadExpandString(const KeyName,ValueName: String; Expand: Boolean = False): String; overload; virtual;
 {C}Function ReadExpandString(const ValueName: String; Expand: Boolean = False): String; overload; virtual;
 {A}procedure ReadMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings); overload; virtual;
 {B}procedure ReadMultiString(const KeyName,ValueName: String; Value: TStrings); overload; virtual;
 {C}procedure ReadMultiString(const ValueName: String; Value: TStrings); overload; virtual;
  {
    ReadBinaryBuffer and ReadBinaryMemory are returning number of bytes actally
    stored in the provided buffer/memory.
  }
 {A}Function ReadBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Buff; Size: TMemSize): TMemSize; overload; virtual;
 {B}Function ReadBinaryBuffer(const KeyName,ValueName: String; out Buff; Size: TMemSize): TMemSize; overload; virtual;
 {C}Function ReadBinaryBuffer(const ValueName: String; out Buff; Size: TMemSize): TMemSize; overload; virtual;
 {A}Function ReadBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize; overload; virtual;
 {B}Function ReadBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize; overload; virtual;
 {C}Function ReadBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize; overload; virtual;
  {
    ReadBinaryMemoryOut returns internally alocated memory space that is
    containing the read data along with its size. Use standard memory
    management functions to free this space.
  }
 {A}Function ReadBinaryMemoryOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Memory: Pointer): TMemSize; overload; virtual;
 {B}Function ReadBinaryMemoryOut(const KeyName,ValueName: String; out Memory: Pointer): TMemSize; overload; virtual;
 {C}Function ReadBinaryMemoryOut(const ValueName: String; out Memory: Pointer): TMemSize; overload; virtual;
 {A}procedure ReadBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream); overload; virtual;
 {B}procedure ReadBinaryStream(const KeyName,ValueName: String; Stream: TStream); overload; virtual;
 {C}procedure ReadBinaryStream(const ValueName: String; Stream: TStream); overload; virtual;
    //--- properties ---
  {
    Following access rights will be used in next call to OpenKey.
  }
    property AccessRightsSys: DWORD read fAccessRightsSys write SetAccessRightsSys;
    property AccessRights: TRXKeyAccessRights read fAccessRights write SetAccessRights;
  {
    Changing the root key will close current key if any is open.
  }
    property RootKeyHandle: HKEY read fRootKeyHandle write SetRootKeyHandle;
    property RootKey: TRXPredefinedKey read fRootKey write SetRootKey;
    property RootKeyString: String read GetRootKeyString;
    property CurrentKeyHandle: HKEY read fCurrentKeyHandle;
    property CurrentKeyName: String read fCurrentKeyName;
  {
    If there is no current key open, then CurrentKeyReflection returns false
    and changing it has no effect.
    Also, this settings is working only on 64bit system, it has no effect and
    returns false on 32bit systems.
  }
    property CurrentKeyReflection: Boolean read GetCurrentKeyReflection write SetCurrentKeyReflection;
    property CurrentKeyPath: String read GetCurrentKeyPath;
  {
    When FlushOnClose is set to true (by default false), the current key is
    flushed before it is closed - meaning all changes made to it are immediately
    saved and are not buffered.
    Use this only when really needed, as it negatively affects performance.
  }
    property FlushOnClose: Boolean read fFlushOnClose write fFlushOnClose;

  end;

implementation

uses
  {$IFNDEF CPU64bit}WindowsVersion,{$ENDIF} StrRect, DynLibUtils;

{$IFDEF FPC_DisableWarns}
  {$DEFINE FPCDWM}
  {$DEFINE W5057:={$WARN 5057 OFF}} // Local variable "$1" does not seem to be initialized
{$ENDIF}

{===============================================================================
--------------------------------------------------------------------------------
                                   TRegistryEx
--------------------------------------------------------------------------------
===============================================================================}
{===============================================================================
    TRegistryEx - external/system functions and constants
===============================================================================}
const
  UNICODE_STRING_MAX_CHARS = 32767;
  _DELETE                  = $00010000;
  READ_CONTROL             = $00020000;

type
  LONG    = LongInt;
  LPBYTE  = ^Byte;
  LSTATUS = Int32;    

// statically linked functions
Function GetSystemRegistryQuota(pdwQuotaAllowed: PDWORD; pdwQuotaUsed: PDWORD): BOOL; stdcall; external 'kernel32.dll';

Function RegOverridePredefKey(hKey: HKEY; hNewHKey: HKEY): LONG; stdcall; external 'advapi32.dll';

Function RegEnumValueW(
  hKey:           HKEY;
  dwIndex:        DWORD;
  lpValueName:    LPWSTR;
  lpcchValueName: LPDWORD;
  lpReserved:     LPDWORD;
  lpType:         LPDWORD;
  lpData:         LPBYTE;
  lpcbData:       LPDWORD
): LSTATUS; stdcall; external 'advapi32.dll';

Function SHDeleteKeyW(hkey: HKEY; pszSubKey: LPCWSTR): LSTATUS; stdcall; external 'shlwapi.dll';
Function SHCopyKeyW(hkeySrc: HKEY; pszSrcSubKey: LPCWSTR; hkeyDest: HKEY; fReserved: DWORD): LSTATUS; stdcall; external 'shlwapi.dll';

Function PathUnExpandEnvStringsW(pszPath: LPCWSTR; pszBuf: LPWSTR; cchBuf: UINT): BOOL; stdcall; external 'shlwapi.dll';

// dynamically linked functions (might not be present on all systems (namely Windows XP 32bit)
var
  RegQueryReflectionKey:    Function(hBase: HKEY; bIsReflectionDisabled: PBOOL): LONG; stdcall = nil;
  RegEnableReflectionKey:   Function(hBase: HKEY): LONG; stdcall = nil;
  RegDisableReflectionKey:  Function(hBase: HKEY): LONG; stdcall = nil;

{===============================================================================
    TRegistryEx - internal functions
===============================================================================}

{$IFDEF FPCDWM}{$PUSH}W5057{$ENDIF}
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
{$IFDEF FPCDWM}{$POP}{$ENDIF}

//------------------------------------------------------------------------------

Function BoolToNum(Value: Boolean): Integer;
begin
If Value then
  Result := -1
else
  Result := 0;
end;

//------------------------------------------------------------------------------

Function ExpandString(const Str: WideString): String;
var
  Temp: WideString;
begin
SetLength(Temp,ExpandEnvironmentStringsW(PWideChar(Str),nil,0));
ExpandEnvironmentStringsW(PWideChar(Str),PWideChar(Temp),Length(Temp));
Result := WideToStr(Copy(Temp,1,Length(Temp) - 1));
end;

//------------------------------------------------------------------------------

Function UnExpandString(const Str: String): WideString;

  Function WStrLen(const Str: WideString): TStrOff;
  var
    i:  Integer;
  begin
    Result := 0;
    For i := 1 to Length(Str) do
      If Str[i] = WideChar(#0) then
        begin
          Result := Pred(i);
          Break{For i};
        end;
  end;
  
var
  Temp: WideString;
begin
Temp := StrToWide(Str);
SetLength(Result,UNICODE_STRING_MAX_CHARS);
If PathUnExpandEnvStringsW(PWideChar(Temp),PWideChar(Result),Length(Result)) then
  SetLength(Result,WStrLen(Result))
else
  Result := StrToWide(Str);
end;

//------------------------------------------------------------------------------

procedure ParseMultiString(const Str: WideString; Strs: TStrings);
var
  i:    TStrOff;
  S,L:  TStrOff;
begin
Strs.Clear;
If Length(Str) > 0 then
  begin
    // parse the multi-string
    S := 1;
    L := 0;
    For i := 1 to Length(Str) do
      If Str[i] = WideChar(#0) then
        begin
          Strs.Add(WideToStr(Copy(Str,S,L)));
          S := Succ(i);
          L := 0;
        end
      else Inc(L);
  end;
end;

//------------------------------------------------------------------------------

Function UnParseMultiString(Strs: TStrings): WideString;
var
  Item:     WideString;
  i:        Integer;
  Len,Pos:  Integer;
begin
If Strs.Count > 0 then
  begin
    // calculate final length/size of saved data
    Len := 1; // list ternimation
    For i := 0 to Pred(Strs.Count) do
      Len := Len + Length(StrToWide(Strs[i])) + 1;
    // preallocate result
    SetLength(Result,Len);
    FillChar(PWideChar(Result)^,Length(Result) * SizeOf(WideChar),0);
    // fill result
    Pos := 1;
    For i := 0 to Pred(Strs.Count) do
      begin
        Item := StrToWide(Strs[i]);
        Move(PWideChar(Item)^,Addr(Result[Pos])^,Length(Item) * SizeOf(WideChar));
        Pos := Pos + Length(Item) + 1;
      end;
  end
else Result := WideChar(#0);
end;

//------------------------------------------------------------------------------

Function IsRelativeKeyName(const KeyName: String): Boolean;
begin
{
  If the key name starts with register path delimiter (backslash, \ , #92), it
  is considered to be an absolute path within the root key, otherwise it is
  considered to be relative to current key.
}
If Length(KeyName) > 0 then
  Result := KeyName[1] <> REG_PATH_DELIMITER
else
  Result := True;
end;

//------------------------------------------------------------------------------

Function TrimKeyName(const KeyName: String): String;
begin
If Length(KeyName) > 1 then
  begin
    Result := KeyName;
    while Result[1] = REG_PATH_DELIMITER do
      Delete(Result,1,1);
    while Result[Length(Result)] = REG_PATH_DELIMITER do
      Delete(Result,Length(Result),1);
  end
else If Length(KeyName) = 1 then
  begin
    If KeyName[1] = REG_PATH_DELIMITER then
      Result := ''
    else
      Result := KeyName;
  end
else Result := '';
end;

//------------------------------------------------------------------------------

Function ConcatKeyNames(const A,B: String): String;
begin
// both A and B are expected to be trimmed
If (Length(A) > 0) and (Length(B) > 0) then
  Result := A + REG_PATH_DELIMITER + B
else If Length(A) > 0 then
  Result := A
else If Length(B) > 0 then
  Result := B
else
  Result := '';
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

Function TranslateCreateOptions(CreateOptions: TRXKeyCreateOptions): DWORD;

  procedure SetResultCreateOption(CreateOption: TRXKeyCreateOption; Flag: DWORD);
  begin
    If CreateOption in CreateOptions then
      Result := Result or Flag;
  end;

begin
Result := 0;
//SetResultCreateOption(kcoNonVolatile,REG_OPTION_NON_VOLATILE);  // REG_OPTION_NON_VOLATILE is 0, so not needed
SetResultCreateOption(kcoVolatile,REG_OPTION_VOLATILE);
SetResultCreateOption(kcoCreateLink,REG_OPTION_CREATE_LINK);
SetResultCreateOption(kcoBackupRestore,REG_OPTION_BACKUP_RESTORE);
SetResultCreateOption(kcoOpenLink,REG_OPTION_OPEN_LINK);
SetResultCreateOption(kcoDontVirtualize,REG_OPTION_DONT_VIRTUALIZE);
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

//------------------------------------------------------------------------------

Function PredefinedKeyToStr(PredefinedKey: HKEY): String; overload;
begin
case PredefinedKey of
  HKEY_CLASSES_ROOT:                Result := 'HKEY_CLASSES_ROOT';
  HKEY_CURRENT_USER:                Result := 'HKEY_CURRENT_USER';
  HKEY_LOCAL_MACHINE:               Result := 'HKEY_LOCAL_MACHINE';
  HKEY_USERS:                       Result := 'HKEY_USERS';
  HKEY_PERFORMANCE_DATA:            Result := 'HKEY_PERFORMANCE_DATA';
  HKEY_PERFORMANCE_TEXT:            Result := 'HKEY_PERFORMANCE_TEXT';
  HKEY_PERFORMANCE_NLSTEXT:         Result := 'HKEY_PERFORMANCE_NLSTEXT';
  HKEY_CURRENT_CONFIG:              Result := 'HKEY_CURRENT_CONFIG';
  HKEY_DYN_DATA:                    Result := 'HKEY_DYN_DATA';
  HKEY_CURRENT_USER_LOCAL_SETTINGS: Result := 'HKEY_CURRENT_USER_LOCAL_SETTINGS';
else
  Result := '';
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function PredefinedKeyToStr(PredefinedKey: TRXPredefinedKey): String; overload;
begin
Result := PredefinedKeyToStr(TranslatePredefinedKey(PredefinedKey));
end;


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
If Value <> fRootKeyHandle then
  begin
    CloseKey;
    fRootKeyHandle := Value;
    fRootKey := TranslatePredefinedKey(Value);
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetRootKey(Value: TRXPredefinedKey);
begin
If Value <> fRootKey then
  begin
    CloseKey;
    fRootKeyHandle := TranslatePredefinedKey(Value);
    fRootKey := Value;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetRootKeyString: String;
begin
Result := PredefinedKeyToStr(fRootKeyHandle);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetCurrentKeyReflection: Boolean;
var
  Value:  BOOL;
begin
If fCurrentKeyHandle <> 0 then
  begin
    If Assigned(RegQueryReflectionKey) then
      begin
        If RegQueryReflectionKey(fCurrentKeyHandle,@Value) = ERROR_SUCCESS then
          Result := not Value // RegQueryReflectionKey indicates whether the reflection is DISABLED
        else
          Result := False;
      end
    else Result := False;
  end
else Result := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetCurrentKeyReflection(Value: Boolean);
begin
If fCurrentKeyHandle <> 0 then
  begin
    If Value then
      begin
        If Assigned(RegEnableReflectionKey) then
          RegEnableReflectionKey(fCurrentKeyHandle);
      end
    else
      begin
        If Assigned(RegDisableReflectionKey) then
          RegDisableReflectionKey(fCurrentKeyHandle)
      end;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetCurrentKeyPath: String;
begin
If Length(fCurrentKeyName) > 0 then
  Result := ConcatKeyNames(RootKeyString,fCurrentKeyName)
else
  result := '';
end;

//------------------------------------------------------------------------------

Function TRegistryEx.AuxOpenKey(RootKey: HKEY; const KeyName: String; AccessRights: DWORD; out NewKey: HKEY): Boolean;
begin
NewKey := 0;
fAuxOpenResult := RegOpenKeyExW(RootKey,PWideChar(StrToWide(KeyName)),0,AccessRights,NewKey);
Result := fAuxOpenResult = ERROR_SUCCESS;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.ChangeCurrentKey(KeyHandle: HKEY; const KeyName: String);
begin
CloseKey;
fCurrentKeyHandle := KeyHandle;
fCurrentKeyName := KeyName;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetWorkingKey(Relative: Boolean; out WorkingKeyName: String): HKEY;
begin
If Relative and (fCurrentKeyHandle <> 0) then
  begin
    WorkingKeyName := fCurrentKeyName;
    Result := fCurrentKeyHandle;
  end
else
  begin
    WorkingKeyName := '';
    Result := fRootKeyHandle;
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetWorkingKey(Relative: Boolean): HKEY;
var
  WorkingKeyName: String;
begin
Result := GetWorkingKey(Relative,WorkingKeyName);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetKeyInfo(Key: HKEY; out KeyInfo: TRXKeyInfo): Boolean;
var
  LastWriteTime:  TFileTime;
begin
Result := False;
FillChar(Addr(KeyInfo)^,SizeOf(TRXKeyInfo),0);
If RegQueryInfoKeyW(Key,nil,nil,nil,@KeyInfo.SubKeys,@KeyInfo.MaxSubKeyLen,
                    @KeyInfo.MaxClassLen,@KeyInfo.Values,
                    @KeyInfo.MaxValueNameLen,@KeyInfo.MaxValueLen,
                    @KeyInfo.SecDescrBytes,@LastWriteTime) = ERROR_SUCCESS then
  begin
    KeyInfo.LastWriteTime := FileTimeToDateTime(LastWriteTime);
    Result := True;
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetSubKeys(Key: HKEY; SubKeys: TStrings);
var
  KeyInfo:  TRXKeyInfo;
  i:        Integer;
  TempStr:  WideString;
  Len:      DWORD;
begin
SubKeys.Clear;
If GetKeyInfo(Key,KeyInfo) then
  begin
    i := 0;  
    SetLength(TempStr,KeyInfo.MaxSubKeyLen + 1);
    while True do
      begin
        Len := Length(TempStr);
        case RegEnumKeyExW(Key,DWORD(i),PWideChar(TempStr),Len,nil,nil,nil,nil) of
          ERROR_SUCCESS:
            SubKeys.Add(WideToStr(Copy(TempStr,1,Len)));
          ERROR_MORE_DATA:
            begin
              SetLength(TempStr,Length(TempStr) * 2);
              Dec(i); // call RegEnumKeyExW again with the same index
            end;
        else
         {ERROR_NO_MORE_ITEMS, or some other error}
          Break{while};
        end;
        Inc(i);
      end;
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueInfo(Key: HKEY; const ValueName: String; out ValueInfo: TRXValueInfo): Boolean;
var
  ValueType:  DWORD;
  DataSize:   DWORD;
begin
Result := False;
FillChar(Addr(ValueInfo)^,SizeOf(TRXValueInfo),0);
If RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,@ValueType,nil,@DataSize) in [ERROR_SUCCESS,ERROR_MORE_DATA] then
  begin
    ValueInfo.ValueType := TranslateValueType(ValueType);
    ValueInfo.DataSize := TMemSize(DataSize);
    Result := True;
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetValues(Key: HKEY; Values: TStrings);
var
  i:        Integer;
  TempStr:  WideString;
  Len:      DWORD;
begin
Values.Clear;
i := 0;
SetLength(TempStr,16383); // limit for a value name length
while True do
  begin
    Len := Length(TempStr);
    case RegEnumValueW(Key,DWORD(i),PWideChar(TempStr),@Len,nil,nil,nil,nil) of
      ERROR_SUCCESS,
      ERROR_MORE_DATA:
        Values.Add(WideToStr(Copy(TempStr,1,Len)));
    else
     {ERROR_NO_MORE_ITEMS, other errors}
      Break{while};
    end;
    Inc(i);
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteSubKeys(Key: HKEY);
var
  SubKeys:  TStringList;
  i:        Integer;
begin
SubKeys := TStringList.Create;
try
  GetSubKeys(Key,SubKeys);
  For i := 0 to Pred(SubKeys.Count) do
    SHDeleteKeyW(Key,PWideChar(StrToWide(SubKeys[i])))
finally
  SubKeys.Free;
end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteValues(Key: HKEY);
var
  Values: TStringList;
  i:      Integer;
begin
Values := TStringList.Create;
try
  GetValues(Key,Values);
  For i := 0 to Pred(Values.Count) do
    RegDeleteValueW(Key,PWideChar(StrToWide(Values[i])))
finally
  Values.Free;
end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveValue(SrcKey: HKEY; const SrcValueName: String; DstKey: HKEY; const DstValueName: String; DeleteSource: Boolean): Boolean;
var
  ValueInfo:  TRXValueInfo;
  Buffer:     Pointer;
  Size:       TMemSize;
begin
Result := False;
If not GetValueInfo(DstKey,DstValueName,ValueInfo) then
  If GetValueInfo(SrcKey,SrcValueName,ValueInfo) then
    begin
      If ValueInfo.DataSize > 0 then
        begin
          If GetValueDataOut(SrcKey,SrcValueName,Buffer,Size,ValueInfo.ValueType) then
            try
              SetValueData(DstKey,DstValueName,Buffer^,Size,ValueInfo.ValueType);
              Result := True;
            finally
              FreeMem(Buffer,Size);
            end;
        end
      else
        begin
          SetValueData(DstKey,DstValueName,nil^,0,ValueInfo.ValueType);
          Result := True;
        end;
      If DeleteSource then
        RegDeleteValueW(SrcKey,PWideChar(StrToWide(SrcValueName)));
    end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetValueData(Key: HKEY; const ValueName: String; const Data; Size: TMemSize; ValueType: TRXValueType);
var
  CallResult: LSTATUS;
begin
CallResult := RegSetValueExW(Key,PWideChar(StrToWide(ValueName)),0,TranslateValueType(ValueType),@Data,DWORD(Size));
If CallResult <> ERROR_SUCCESS then
  raise ERXRegistryWriteError.CreateFmt('TRegistryEx.SetValueData: Unable to write value "%s" (%d).',[ValueName,CallResult]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.SetValueData(Key: HKEY; const ValueName: String; Data: Integer);
var
  Temp: DWORD;
begin
Temp := DWORD(Data);
SetValueData(Key,ValueName,Temp,SizeOf(DWORD),vtDWord);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteMacro(const TypeName: String; RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value; Size: TMemSize; ValueType: TRXValueType);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_SET_VALUE,TempKey) then
  try
    SetValueData(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else raise ERXInvalidKey.CreateFmt('TRegistryEx.Write%s: Unable to open key "%s" for writing (%d).',
  [TypeName,ConcatKeyNames(PredefinedKeytoStr(RootKey),TrimKeyName(KeyName)),fAuxOpenResult]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteMacro(const TypeName,KeyName,ValueName: String; const Value; Size: TMemSize; ValueType: TRXValueType);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_SET_VALUE,TempKey) then
  try
    SetValueData(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else raise ERXInvalidKey.CreateFmt('TRegistryEx.Write%s: Unable to open key "%s" for writing (%d).',
  [TypeName,KeyName,fAuxOpenResult]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteMacro(const TypeName: String; RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Integer);
var
  Temp: DWORD;
begin
Temp := DWORD(Value);
WriteMacro(TypeName,RootKey,KeyName,ValueName,Temp,SizeOf(DWORD),vtDWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteMacro(const TypeName,KeyName,ValueName: String; Value: Integer);
var
  Temp: DWORD;
begin
Temp := DWORD(Value);
WriteMacro(TypeName,KeyName,ValueName,Temp,SizeOf(DWORD),vtDWord);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueDataOut(Key: HKEY; const ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  RegDataSize:  DWORD;
  RegValueType: DWORD;
begin
Result := False;
If RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,@RegValueType,nil,@RegDataSize) in [ERROR_SUCCESS,ERROR_MORE_DATA] then
  If TranslateValueType(RegValueType) = ValueType then
    begin
      If RegDataSize <> 0 then
        begin
          // non-empty data
          // it is necessary to keep the size, as RegQueryValueExW can fill the RegDataSize with bogus data
          Size := TMemSize(RegDataSize);
          GetMem(Mem,Size);
          while True do
            begin
              case RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,nil,Mem,@RegDataSize) of
                ERROR_SUCCESS:    begin
                                    If TMemSize(RegDataSize) <> Size then
                                      begin
                                        Size := TMemSize(RegDataSize);
                                        ReallocMem(Mem,Size);
                                      end;
                                    Result := True;
                                    Break{while};
                                  end;
                ERROR_MORE_DATA:  begin
                                    // do not call realloc, there is no need to preserve any data
                                    FreeMem(Mem,Size);
                                    Size := TMemSize(RegDataSize) * 2;
                                    GetMem(Mem,Size);
                                    RegDataSize := DWORD(Size);
                                  end;
              else
               {some error...}
                Break{while};
              end;
            end;
          If not Result then
            begin
              FreeMem(Mem,Size);
              Mem := nil;
              Size := 0;
            end;
        end
      else
        begin
          // zero-size data
          Mem := nil;
          Size := 0;
          Result := True;
        end;
    end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueDataOut(Key: HKEY; const ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean;
var
  RegDataSize:  DWORD;
  RegValueType: DWORD;
begin
Result := False;
If RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,@RegValueType,nil,@RegDataSize) in [ERROR_SUCCESS,ERROR_MORE_DATA] then
  If TranslateValueType(RegValueType) = ValueType then
    begin
      If RegDataSize <> 0 then
        begin
          // non-empty data
          SetLength(Str,RegDataSize div SizeOf(WideChar));
          RegDataSize := DWORD(Length(Str) * SizeOf(WideChar));
          while True do
            begin
              case RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,nil,PByte(PWideChar(Str)),@RegDataSize) of
                ERROR_SUCCESS:    begin
                                    If RegDataSize <> DWORD(Length(Str) * SizeOf(WideChar)) then
                                      SetLength(Str,RegDataSize div SizeOf(WideChar));
                                    Result := True;
                                    Break{while};
                                  end;
                ERROR_MORE_DATA:  begin
                                    SetLength(Str,0); // prevent copying of data
                                    SetLength(Str,RegDataSize div SizeOf(WideChar));
                                    RegDataSize := DWORD(Length(Str) * SizeOf(WideChar));
                                  end;
              else
               {some error...}
                Break{while};
              end;
            end;
          If Result then
            begin
              // remove terminating zero
              If Length(Str) > 0 then
                If Str[Length(Str)] = WideChar(#0) then
                  SetLength(Str,Length(Str) - 1);
            end
          else Str := '';
        end
      else
        begin
          // zero-size data
          Str := '';
          Result := True;
        end;
    end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueDataExtBuff(Key: HKEY; const ValueName: String; out Data; var Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  RegDataSize:  DWORD;
  RegValueType: DWORD;
begin
RegDataSize := DWORD(Size);
If RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,@RegValueType,@Data,@RegDataSize) = ERROR_SUCCESS then
  begin
    Result := TranslateValueType(ValueType) = RegValueType;
    If Result then
      Size := TMemSize(RegDataSize);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueDataStat(Key: HKEY; const ValueName: String; out Data; Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  RegDataSize:  DWORD;
  RegValueType: DWORD;
begin
RegDataSize := DWORD(Size);
If RegQueryValueExW(Key,PWideChar(StrToWide(ValueName)),nil,@RegValueType,@Data,@RegDataSize) = ERROR_SUCCESS then
{
  This function is intended only for invariant-size data, so to consider it
  successful, the amount of read data must equal to what was requested, and
  actual data type must match requested type.
}
  Result := (TMemSize(RegDataSize) = Size) and (TranslateValueType(ValueType) = RegValueType)
else
  Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueDataStat(Key: HKEY; const ValueName: String; out Data: Integer): Boolean;
var
  Temp: DWORD;
begin
Result := GetValueDataStat(Key,ValueName,Temp,SizeOf(DWORD),vtDWord);
Data := Integer(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadMacroOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataOut(TempKey,ValueName,Mem,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacroOut(const KeyName,ValueName: String; out Mem: Pointer; out Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataOut(TempKey,ValueName,Mem,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacroOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataOut(TempKey,ValueName,Str,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacroOut(const KeyName,ValueName: String; out Str: WideString; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataOut(TempKey,ValueName,Str,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadMacroExtBuff(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value; var Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataExtBuff(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacroExtBuff(const KeyName,ValueName: String; out Value; var Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataExtBuff(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadMacro(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value; Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataStat(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacro(const KeyName,ValueName: String; out Value; Size: TMemSize; ValueType: TRXValueType): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueDataStat(TempKey,ValueName,Value,Size,ValueType);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacro(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Success: Boolean): Integer;
var
  Temp: DWORD;
begin
Success := TryReadMacro(RootKey,KeyName,ValueName,Temp,SizeOf(DWORD),vtDWord);
Result := Integer(Temp);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMacro(const KeyName,ValueName: String; out Success: Boolean): Integer;
var
  Temp: DWORD;
begin
Success := TryReadMacro(KeyName,ValueName,Temp,SizeOf(DWORD),vtDWord);
Result := Integer(Temp);
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
fAuxOpenResult := ERROR_SUCCESS;
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
  Result := 0;
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
  Result := 0;
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

//------------------------------------------------------------------------------

Function TRegistryEx.OverridePredefinedKey(PredefinedKey: TRXPredefinedKey; RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),STANDARD_RIGHTS_READ,TempKey) then
  try
    Result := RegOverridePredefKey(TranslatePredefinedKey(PredefinedKey),TempKey) = ERROR_SUCCESS
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OverridePredefinedKey(PredefinedKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),STANDARD_RIGHTS_READ,TempKey) then
  try
    Result := RegOverridePredefKey(TranslatePredefinedKey(PredefinedKey),TempKey) = ERROR_SUCCESS
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OverridePredefinedKey(PredefinedKey: TRXPredefinedKey): Boolean;
begin
If fCurrentKeyHandle <> 0 then
  Result := RegOverridePredefKey(TranslatePredefinedKey(PredefinedKey),fCurrentKeyHandle) = ERROR_SUCCESS
else
  Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.RestorePredefinedKey(PredefinedKey: TRXPredefinedKey): Boolean;
begin
Result := RegOverridePredefKey(TranslatePredefinedKey(PredefinedKey),0) = ERROR_SUCCESS;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.OpenKey(RootKey: TRXPredefinedKey; const KeyName: String; CanCreate: Boolean; out Created: Boolean; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean;
var
  TempKey:      HKEY;
  Disposition:  DWORD;
begin
TempKey := 0;
If CanCreate then
  begin
    Result := RegCreateKeyExW(TranslatePredefinedKey(RootKey),
                              PWideChar(StrToWide(TrimKeyName(KeyName))),
                              0,nil,TranslateCreateOptions(CreateOptions),
                              fAccessRightsSys,nil,TempKey,@Disposition) = ERROR_SUCCESS;
    case Disposition of
      REG_CREATED_NEW_KEY:      Created := True;
      REG_OPENED_EXISTING_KEY:  Created := False;
    else
      raise ERXInvalidValue.CreateFmt('TRegistryEx.OpenKey: Invalid disposition (%d).',[Disposition]);
    end;
  end
else
  begin
    Result := RegOpenKeyExW(TranslatePredefinedKey(RootKey),
                            PWideChar(StrToWide(TrimKeyName(KeyName))),
                            0,fAccessRightsSys,TempKey) = ERROR_SUCCESS;
    Created := False;
  end;
If Result then
  begin
    fRootKeyHandle := TranslatePredefinedKey(RootKey);
    fRootKey := RootKey;
    ChangeCurrentKey(TempKey,TrimKeyName(KeyName));
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OpenKey(const KeyName: String; CanCreate: Boolean; out Created: Boolean; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean;
var
  TempKey:        HKEY;
  WorkingKeyName: String;
  Disposition:    DWORD;
begin
TempKey := 0;
If CanCreate then
  begin
    Result := RegCreateKeyExW(GetWorkingKey(IsRelativeKeyName(KeyName),WorkingKeyName),
                              PWideChar(StrToWide(TrimKeyName(KeyName))),
                              0,nil,TranslateCreateOptions(CreateOptions),
                              fAccessRightsSys,nil,TempKey,@Disposition) = ERROR_SUCCESS;
    case Disposition of
      REG_CREATED_NEW_KEY:      Created := True;
      REG_OPENED_EXISTING_KEY:  Created := False;
    else
      raise ERXInvalidValue.CreateFmt('TRegistryEx.OpenKey: Invalid disposition (%d).',[Disposition]);
    end;
  end
else
  begin
    Result := RegOpenKeyExW(GetWorkingKey(IsRelativeKeyName(KeyName),WorkingKeyName),
                            PWideChar(StrToWide(TrimKeyName(KeyName))),
                            0,fAccessRightsSys,TempKey) = ERROR_SUCCESS;
    Created := False;
  end;
If Result then
  ChangeCurrentKey(TempKey,ConcatKeyNames(WorkingKeyName,TrimKeyName(KeyName)));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OpenKey(RootKey: TRXPredefinedKey; const KeyName: String; CanCreate: Boolean): Boolean;
var
  Created:  Boolean;
begin
Result := OpenKey(RootKey,KeyName,CanCreate,Created);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OpenKey(const KeyName: String; CanCreate: Boolean): Boolean;
var
  Created:  Boolean;
begin
Result := OpenKey(KeyName,CanCreate,Created);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.OpenKeyReadOnly(RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  AccessRightsTemp: DWORD;
  TempKey:          HKEY;
begin
TempKey := 0;
// preserve karWoW64_32Key and karWoW64_64Key from current access rights
AccessRightsTemp := TranslateAccessRights(karRead + (fAccessRights * karWoW64_Res));
Result := RegOpenKeyExW(TranslatePredefinedKey(RootKey),
                        PWideChar(StrToWide(TrimKeyName(KeyName))),
                        0,AccessRightsTemp,TempKey) = ERROR_SUCCESS;
If Result then
  begin
    SetAccessRightsSys(AccessRightsTemp);
    fRootKeyHandle := TranslatePredefinedKey(RootKey);
    fRootKey := RootKey;    
    ChangeCurrentKey(TempKey,TrimKeyName(KeyName));
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.OpenKeyReadOnly(const KeyName: String): Boolean;
var
  AccessRightsTemp: DWORD;
  TempKey:          HKEY;
  WorkingKeyName:   String;
begin
TempKey := 0;
AccessRightsTemp := TranslateAccessRights(karRead + (fAccessRights * karWoW64_Res));
Result := RegOpenKeyExW(GetWorkingKey(IsRelativeKeyName(KeyName),WorkingKeyName),
                        PWideChar(StrToWide(TrimKeyName(KeyName))),
                        0,AccessRightsTemp,TempKey) = ERROR_SUCCESS;
If Result then
  begin
    SetAccessRightsSys(AccessRightsTemp);
    ChangeCurrentKey(TempKey,ConcatKeyNames(WorkingKeyName,TrimKeyName(KeyName)));
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.KeyExists(RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),STANDARD_RIGHTS_READ,TempKey) then
  try
    Result := TempKey <> 0;
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.KeyExists(const KeyName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),STANDARD_RIGHTS_READ,TempKey) then
  try
    Result := TempKey <> 0;
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CreateKey(RootKey: TRXPredefinedKey; const KeyName: String; AccessRights: TRXKeyAccessRights = karAllAccess; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean;
var
  TempKey:  HKEY;
begin
TempKey := 0;
If RegCreateKeyExW(TranslatePredefinedKey(RootKey),
                   PWideChar(StrToWide(TrimKeyName(KeyName))),0,nil,
                   TranslateCreateOptions(CreateOptions),
                   TranslateAccessRights(AccessRights),nil,TempKey,nil) = ERROR_SUCCESS then
  begin
    RegCloseKey(TempKey);
    Result := True;
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CreateKey(const KeyName: String; AccessRights: TRXKeyAccessRights = karAllAccess; CreateOptions: TRXKeyCreateOptions = [kcoNonVolatile]): Boolean;
var
  TempKey:  HKEY;
begin
TempKey := 0;
If RegCreateKeyExW(GetWorkingKey(IsRelativeKeyName(KeyName)),
                   PWideChar(StrToWide(TrimKeyName(KeyName))),0,nil,
                   TranslateCreateOptions(CreateOptions),
                   TranslateAccessRights(AccessRights),nil,TempKey,nil) = ERROR_SUCCESS then
  begin
    RegCloseKey(TempKey);
    Result := True;
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.DeleteKey(RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
begin
Result := SHDeleteKeyW(TranslatePredefinedKey(RootKey),PWideChar(StrToWide(TrimKeyName(KeyName)))) = ERROR_SUCCESS;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.DeleteKey(const KeyName: String): Boolean;
begin
Result := SHDeleteKeyW(GetWorkingKey(IsRelativeKeyName(KeyName)),PWideChar(StrToWide(TrimKeyName(KeyName)))) = ERROR_SUCCESS;
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

Function TRegistryEx.GetKeyInfo(RootKey: TRXPredefinedKey; const KeyName: String; out KeyInfo: TRXKeyInfo): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetKeyInfo(TempKey,KeyInfo);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetKeyInfo(const KeyName: String; out KeyInfo: TRXKeyInfo): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetKeyInfo(TempKey,KeyInfo);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetKeyInfo(out KeyInfo: TRXKeyInfo): Boolean;
begin
Result := GetKeyInfo(GetWorkingKey(True),KeyInfo);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.HasSubKeys(RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(RootKey,KeyName,KeyInfo) then
  Result := KeyInfo.SubKeys > 0
else
  Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.HasSubKeys(const KeyName: String): Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(KeyName,KeyInfo) then
  Result := KeyInfo.SubKeys > 0
else
  Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.HasSubKeys: Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(KeyInfo) then
  Result := KeyInfo.SubKeys > 0
else
  Result := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetSubKeys(RootKey: TRXPredefinedKey; const KeyName: String; SubKeys: TStrings);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_ENUMERATE_SUB_KEYS or KEY_QUERY_VALUE,TempKey) then
  try
    GetSubKeys(TempKey,SubKeys);
  finally
    RegCloseKey(TempKey);
  end
else SubKeys.Clear;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.GetSubKeys(const KeyName: String; SubKeys: TStrings);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_ENUMERATE_SUB_KEYS or KEY_QUERY_VALUE,TempKey) then
  try
    GetSubKeys(TempKey,SubKeys);
  finally
    RegCloseKey(TempKey);
  end
else SubKeys.Clear;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.GetSubKeys(SubKeys: TStrings);
begin
GetSubKeys(GetWorkingKey(True),SubKeys);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueInfo(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out ValueInfo: TRXValueInfo): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueInfo(TempKey,ValueName,ValueInfo);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueInfo(const KeyName,ValueName: String; out ValueInfo: TRXValueInfo): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    Result := GetValueInfo(TempKey,ValueName,ValueInfo);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueInfo(const ValueName: String; out ValueInfo: TRXValueInfo): Boolean;
begin
Result := GetValueInfo(GetWorkingKey(True),ValueName,ValueInfo);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.HasValues(RootKey: TRXPredefinedKey; const KeyName: String): Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(RootKey,KeyName,KeyInfo) then
  Result := KeyInfo.Values > 0
else
  Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.HasValues(const KeyName: String): Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(KeyName,KeyInfo) then
  Result := KeyInfo.Values > 0
else
  Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.HasValues: Boolean;
var
  KeyInfo:  TRXKeyInfo;
begin
If GetKeyInfo(KeyInfo) then
  Result := KeyInfo.Values > 0
else
  Result := False;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.GetValues(RootKey: TRXPredefinedKey; const KeyName: String; Values: TStrings);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    GetValues(TempKey,Values);
  finally
    RegCloseKey(TempKey);
  end
else Values.Clear;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.GetValues(const KeyName: String; Values: TStrings);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE,TempKey) then
  try
    GetValues(TempKey,Values);
  finally
    RegCloseKey(TempKey);
  end
else Values.Clear;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.GetValues(Values: TStrings);
begin
GetValues(GetWorkingKey(True),Values);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueType(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TRXValueType;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(RootKey,KeyName,ValueName,ValueInfo) then
  Result := ValueInfo.ValueType
else
  Result := vtUnknown;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueType(const KeyName,ValueName: String): TRXValueType;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(KeyName,ValueName,ValueInfo) then
  Result := ValueInfo.ValueType
else
  Result := vtUnknown;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueType(const ValueName: String): TRXValueType;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(ValueName,ValueInfo) then
  Result := ValueInfo.ValueType
else
  Result := vtUnknown;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.GetValueDataSize(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TMemSize;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(RootKey,KeyName,ValueName,ValueInfo) then
  Result := ValueInfo.DataSize
else
  Result := 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueDataSize(const KeyName,ValueName: String): TMemSize;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(KeyName,ValueName,ValueInfo) then
  Result := ValueInfo.DataSize
else
  Result := 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.GetValueDataSize(const ValueName: String): TMemSize;
var
  ValueInfo:  TRXValueInfo;
begin
If GetValueInfo(ValueName,ValueInfo) then
  Result := ValueInfo.DataSize
else
  Result := 0;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ValueExists(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean;
var
  ValueInfo:  TRXValueInfo;
begin
Result := GetValueInfo(RootKey,KeyName,ValueName,ValueInfo);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ValueExists(const KeyName,ValueName: String): Boolean;
var
  ValueInfo:  TRXValueInfo;
begin
Result := GetValueInfo(KeyName,ValueName,ValueInfo);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ValueExists(const ValueName: String): Boolean;
var
  ValueInfo:  TRXValueInfo;
begin
Result := GetValueInfo(ValueName,ValueInfo);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.DeleteValue(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_SET_VALUE,TempKey) then
  try
    Result := RegDeleteValueW(TempKey,PWideChar(StrToWide(ValueName))) = ERROR_SUCCESS
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.DeleteValue(const KeyName,ValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_SET_VALUE,TempKey) then
  try
    Result := RegDeleteValueW(TempKey,PWideChar(StrToWide(ValueName))) = ERROR_SUCCESS
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.DeleteValue(const ValueName: String): Boolean;
begin
Result := RegDeleteValueW(GetWorkingKey(True),PWideChar(StrToWide(ValueName))) = ERROR_SUCCESS
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteSubKeys(RootKey: TRXPredefinedKey; const KeyName: String);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),
     KEY_ENUMERATE_SUB_KEYS or KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    DeleteSubKeys(TempKey);
  finally
    RegCloseKey(TempKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteSubKeys(const KeyName: String);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),
     KEY_ENUMERATE_SUB_KEYS or KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    DeleteSubKeys(TempKey);
  finally
    RegCloseKey(TempKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteSubKeys;
begin
DeleteSubKeys(GetWorkingKey(True));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteValues(RootKey: TRXPredefinedKey; const KeyName: String);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    DeleteValues(TempKey);
  finally
    RegCloseKey(TempKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteValues(const KeyName: String);
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    DeleteValues(TempKey);
  finally
    RegCloseKey(TempKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteValues;
begin
DeleteValues(GetWorkingKey(True));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.DeleteContent(RootKey: TRXPredefinedKey; const KeyName: String);
begin
DeleteSubKeys(RootKey,KeyName);
DeleteValues(RootKey,KeyName);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteContent(const KeyName: String);
begin
DeleteSubKeys(KeyName);
DeleteValues(KeyName);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.DeleteContent;
begin
DeleteSubKeys;
DeleteValues;
end;

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
    //Source := OpenKeyInternal(SrcKey,fAccessRightsSys);
    //Destination := OpenKeyInternal(DestKey,fAccessRightsSys);
    If AuxOpenKey(fCurrentKeyHandle,SrcKey,KEY_ALL_ACCESS,Source) then
      try
        If AuxOpenKey(fCurrentKeyHandle,DestKey,KEY_ALL_ACCESS,Destination) then
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

Function TRegistryEx.CopyValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,False);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,False);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValue(const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,False);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValue(const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,False);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CopyValueTo(const SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  DstKey: HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
  try
    Result := MoveValue(GetWorkingKey(True),SrcValueName,DstKey,DstValueName,False);
  finally
    RegCloseKey(DstKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValueTo(const SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  DstKey: HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
  try
    Result := MoveValue(GetWorkingKey(True),SrcValueName,DstKey,DstValueName,False);
  finally
    RegCloseKey(DstKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CopyValueFrom(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean;
var
  SrcKey: HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    Result := MoveValue(SrcKey,SrcValueName,GetWorkingKey(True),DstValueName,False);
  finally
    RegCloseKey(SrcKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValueFrom(const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean;
var
  SrcKey: HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_QUERY_VALUE,SrcKey) then
  try
    Result := MoveValue(SrcKey,SrcValueName,GetWorkingKey(True),DstValueName,False);
  finally
    RegCloseKey(SrcKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.CopyValueIn(RootKey: TRXPredefinedKey; const KeyName,SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,False);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValueIn(const KeyName,SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,False);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.CopyValueIn(const SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
TempKey := GetWorkingKey(True);
Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,False);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,True);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValue(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,True);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValue(const SrcKeyName,SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,True);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValue(const SrcKeyName,SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  SrcKey,DstKey:  HKEY;
begin
Result := False;
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
      try
        Result := MoveValue(SrcKey,SrcValueName,DstKey,DstValueName,True);
      finally
        RegCloseKey(DstKey);
      end;
  finally
    RegCloseKey(SrcKey);
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveValueTo(const SrcValueName: String; DstRootKey: TRXPredefinedKey; const DstKeyName,DstValueName: String): Boolean;
var
  DstKey: HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(DstRootKey),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
  try
    Result := MoveValue(GetWorkingKey(True),SrcValueName,DstKey,DstValueName,True);
  finally
    RegCloseKey(DstKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValueTo(const SrcValueName: String; const DstKeyName,DstValueName: String): Boolean;
var
  DstKey: HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(DstKeyName)),TrimKeyName(DstKeyName),KEY_SET_VALUE,DstKey) then
  try
    Result := MoveValue(GetWorkingKey(True),SrcValueName,DstKey,DstValueName,True);
  finally
    RegCloseKey(DstKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveValueFrom(SrcRootKey: TRXPredefinedKey; const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean;
var
  SrcKey: HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(SrcRootKey),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    Result := MoveValue(SrcKey,SrcValueName,GetWorkingKey(True),DstValueName,True);
  finally
    RegCloseKey(SrcKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValueFrom(const SrcKeyName,SrcValueName: String; const DstValueName: String): Boolean;
var
  SrcKey: HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(SrcKeyName)),TrimKeyName(SrcKeyName),KEY_SET_VALUE or KEY_QUERY_VALUE,SrcKey) then
  try
    Result := MoveValue(SrcKey,SrcValueName,GetWorkingKey(True),DstValueName,True);
  finally
    RegCloseKey(SrcKey);
  end
else Result := False;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.MoveValueIn(RootKey: TRXPredefinedKey; const KeyName,SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(TranslatePredefinedKey(RootKey),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,True);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValueIn(const KeyName,SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
If AuxOpenKey(GetWorkingKey(IsRelativeKeyName(KeyName)),TrimKeyName(KeyName),KEY_QUERY_VALUE or KEY_SET_VALUE,TempKey) then
  try
    Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,True);
  finally
    RegCloseKey(TempKey);
  end
else Result := False;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.MoveValueIn(const SrcValueName,DstValueName: String): Boolean;
var
  TempKey:  HKEY;
begin
TempKey := GetWorkingKey(True);
Result := MoveValue(TempKey,SrcValueName,TempKey,DstValueName,True);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.RenameValue(RootKey: TRXPredefinedKey; const KeyName,OldName,NewName: String): Boolean;
begin
Result := MoveValueIn(RootKey,KeyName,OldName,NewName);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.RenameValue(const KeyName,OldName, NewName: String): Boolean;
begin
Result := MoveValueIn(KeyName,OldName,NewName);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.RenameValue(const OldName, NewName: String): Boolean;
begin
Result := MoveValueIn(OldName,NewName);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Boolean);
begin
WriteMacro('Bool',RootKey,KeyName,ValueName,BoolToNum(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBool(const KeyName,ValueName: String; Value: Boolean);
begin
WriteMacro('Bool',KeyName,ValueName,BoolToNum(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBool(const ValueName: String; Value: Boolean);
begin
SetValueData(GetWorkingKey(True),ValueName,BoolToNum(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int8);
begin
WriteMacro('Int8',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt8(const KeyName,ValueName: String; Value: Int8);
begin
WriteMacro('Int8',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt8(const ValueName: String; Value: Int8);
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt8);
begin
WriteMacro('UInt8',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt8(const KeyName,ValueName: String; Value: UInt8);
begin
WriteMacro('UInt8',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt8(const ValueName: String; Value: UInt8);
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int16);
begin
WriteMacro('Int16',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt16(const KeyName,ValueName: String; Value: Int16);
begin
WriteMacro('Int16',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt16(const ValueName: String; Value: Int16); 
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt16);
begin
WriteMacro('UInt16',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt16(const KeyName,ValueName: String; Value: UInt16);
begin
WriteMacro('UInt16',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt16(const ValueName: String; Value: UInt16); 
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int32);
begin
WriteMacro('Int32',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt32(const KeyName,ValueName: String; Value: Int32);
begin
WriteMacro('Int32',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt32(const ValueName: String; Value: Int32);
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt32);
begin
WriteMacro('UInt32',RootKey,KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt32(const KeyName,ValueName: String; Value: UInt32);
begin
WriteMacro('UInt32',KeyName,ValueName,Integer(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt32(const ValueName: String; Value: UInt32); 
begin
SetValueData(GetWorkingKey(True),ValueName,Integer(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Int64);
begin
WriteMacro('Int64',RootKey,KeyName,ValueName,Value,SizeOf(Int64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt64(const KeyName,ValueName: String; Value: Int64);
begin
WriteMacro('Int64',KeyName,ValueName,Value,SizeOf(Int64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInt64(const ValueName: String; Value: Int64);
begin
SetValueData(GetWorkingKey(True),ValueName,Value,SizeOf(Int64),vtQWord);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: UInt64);
begin
WriteMacro('UInt64',RootKey,KeyName,ValueName,Value,SizeOf(UInt64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt64(const KeyName,ValueName: String; Value: UInt64);
begin
WriteMacro('UInt64',KeyName,ValueName,Value,SizeOf(UInt64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteUInt64(const ValueName: String; Value: UInt64);
begin
SetValueData(GetWorkingKey(True),ValueName,Value,SizeOf(Int64),vtQWord);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Integer);
begin
WriteMacro('Integer',RootKey,KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInteger(const KeyName,ValueName: String; Value: Integer);
begin
WriteMacro('Integer',KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteInteger(const ValueName: String; Value: Integer);
begin
SetValueData(GetWorkingKey(True),ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Float32);
begin
WriteMacro('Float32',RootKey,KeyName,ValueName,Value,SizeOf(Float32),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat32(const KeyName,ValueName: String; Value: Float32);
begin
WriteMacro('Float32',KeyName,ValueName,Value,SizeOf(Float32),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat32(const ValueName: String; Value: Float32);
begin
SetValueData(GetWorkingKey(True),ValueName,Value,SizeOf(Float32),vtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Float64);
begin
WriteMacro('Float64',RootKey,KeyName,ValueName,Value,SizeOf(Float64),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat64(const KeyName,ValueName: String; Value: Float64);
begin
WriteMacro('Float64',KeyName,ValueName,Value,SizeOf(Float64),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat64(const ValueName: String; Value: Float64);
begin
SetValueData(GetWorkingKey(True),ValueName,Value,SizeOf(Float64),vtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Double);
begin
WriteFloat64(RootKey,KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat(const KeyName,ValueName: String; Value: Double);
begin
WriteFloat64(KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteFloat(const ValueName: String; Value: Double);
begin
WriteFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: Currency);
begin
WriteMacro('Currency',RootKey,KeyName,ValueName,Value,SizeOf(Currency),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteCurrency(const KeyName,ValueName: String; Value: Currency);
begin
WriteMacro('Currency',KeyName,ValueName,Value,SizeOf(Currency),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteCurrency(const ValueName: String; Value: Currency);
begin
SetValueData(GetWorkingKey(True),ValueName,Value,SizeOf(Currency),vtBinary);
end;
 
//------------------------------------------------------------------------------

procedure TRegistryEx.WriteDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(RootKey,KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteDateTime(const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteDateTime(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(RootKey,KeyName,ValueName,Int(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteDate(const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(KeyName,ValueName,Int(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteDate(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Int(Value));
end;
 
//------------------------------------------------------------------------------

procedure TRegistryEx.WriteTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(RootKey,KeyName,ValueName,Frac(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteTime(const KeyName,ValueName: String; Value: TDateTime);
begin
WriteFloat64(KeyName,ValueName,Frac(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteTime(const ValueName: String; Value: TDateTime);
begin
WriteFloat64(ValueName,Frac(Value));
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value: String);
var
  Temp: WideString;
begin
Temp := StrToWide(Value);
WriteMacro('String',RootKey,KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1{terminating zero}) * SizeOf(WideChar),vtString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteString(const KeyName,ValueName: String; const Value: String);
var
  Temp: WideString;
begin
Temp := StrToWide(Value);
WriteMacro('String',KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteString(const ValueName: String; const Value: String);
var
  Temp: WideString;
begin
Temp := StrToWide(Value);
SetValueData(GetWorkingKey(True),ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtString);
end;
 
//------------------------------------------------------------------------------

procedure TRegistryEx.WriteExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Value: String; UnExpand: Boolean = False);
var
  Temp: WideString;
begin
If UnExpand then
  Temp := UnExpandString(Value)
else
  Temp := StrToWide(Value);
WriteMacro('ExpandString',RootKey,KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtExpandString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteExpandString(const KeyName,ValueName: String; const Value: String; UnExpand: Boolean = False);
var
  Temp: WideString;
begin
If UnExpand then
  Temp := UnExpandString(Value)
else
  Temp := StrToWide(Value);
WriteMacro('ExpandString',KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtExpandString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteExpandString(const ValueName: String; const Value: String; UnExpand: Boolean = False);
var
  Temp: WideString;
begin
If UnExpand then
  Temp := UnExpandString(Value)
else
  Temp := StrToWide(Value);
SetValueData(GetWorkingKey(True),ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtExpandString);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings);
var
  Temp: WideString;
begin
Temp := UnParseMultiString(Value);
WriteMacro('MultiString',RootKey,KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtMultiString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteMultiString(const KeyName,ValueName: String; Value: TStrings);
var
  Temp: WideString;
begin
Temp := UnParseMultiString(Value);
WriteMacro('MultiString',KeyName,ValueName,PWideChar(Temp)^,(Length(Temp) + 1) * SizeOf(WideChar),vtMultiString);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteMultiString(const ValueName: String; Value: TStrings);
var
  Temp: WideString;
begin
Temp := UnParseMultiString(Value);
SetValueData(GetWorkingKey(True),ValueName,PWideChar(Temp)^,Length(Temp) * SizeOf(WideChar),vtMultiString);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Buff; Size: TMemSize);
begin
WriteMacro('BinaryBuffer',RootKey,KeyName,ValueName,Buff,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryBuffer(const KeyName,ValueName: String; const Buff; Size: TMemSize);
begin
WriteMacro('BinaryBuffer',KeyName,ValueName,Buff,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryBuffer(const ValueName: String; const Buff; Size: TMemSize);
begin
SetValueData(GetWorkingKey(True),ValueName,Buff,Size,vtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize);
begin
WriteMacro('BinaryMemory',RootKey,KeyName,ValueName,Memory^,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize);
begin
WriteMacro('BinaryMemory',KeyName,ValueName,Memory^,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize);
begin
SetValueData(GetWorkingKey(True),ValueName,Memory^,Size,vtBinary);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream; Position, Count: Int64);
var
  Buffer: Pointer;
begin
GetMem(Buffer,TMemSize(Count));
try
  Stream.Seek(Position,soBeginning);
  Stream.ReadBuffer(Buffer^,Count);
  WriteMacro('BinaryStream',RootKey,KeyName,ValueName,Buffer^,TMemSize(Count),vtBinary);
finally
  FreeMem(Buffer,TMemSize(Count));
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryStream(const KeyName,ValueName: String; Stream: TStream; Position, Count: Int64);
var
  Buffer: Pointer;
begin
GetMem(Buffer,TMemSize(Count));
try
  Stream.Seek(Position,soBeginning);
  Stream.ReadBuffer(Buffer^,Count);
  WriteMacro('BinaryStream',KeyName,ValueName,Buffer^,TMemSize(Count),vtBinary);
finally
  FreeMem(Buffer,TMemSize(Count));
end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryStream(const ValueName: String; Stream: TStream; Position, Count: Int64);
var
  Buffer: Pointer;
begin
GetMem(Buffer,TMemSize(Count));
try
  Stream.Seek(Position,soBeginning);
  Stream.ReadBuffer(Buffer^,Count);
  SetValueData(GetWorkingKey(True),ValueName,Buffer^,TMemSize(Count),vtBinary);
finally
  FreeMem(Buffer,TMemSize(Count));
end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.WriteBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream);
begin
WriteBinaryStream(RootKey,KeyName,ValueName,Stream,0,Stream.Size);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryStream(const KeyName,ValueName: String; Stream: TStream);
begin
WriteBinaryStream(KeyName,ValueName,Stream,0,Stream.Size);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.WriteBinaryStream(const ValueName: String; Stream: TStream);
begin
WriteBinaryStream(ValueName,Stream,0,Stream.Size);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Boolean): Boolean;
begin
Value := TryReadMacro(RootKey,KeyName,ValueName,Result) <> 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBool(const KeyName,ValueName: String; out Value: Boolean): Boolean;
begin
Value := TryReadMacro(KeyName,ValueName,Result) <> 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBool(const ValueName: String; out Value: Boolean): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := Temp <> 0;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int8): Boolean;
begin
Value := Int8(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt8(const KeyName,ValueName: String; out Value: Int8): Boolean;
begin
Value := Int8(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt8(const ValueName: String; out Value: Int8): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := Int8(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt8): Boolean;
begin
Value := UInt8(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt8(const KeyName,ValueName: String; out Value: UInt8): Boolean;
begin
Value := UInt8(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt8(const ValueName: String; out Value: UInt8): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := UInt8(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int16): Boolean;
begin
Value := Int16(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt16(const KeyName,ValueName: String; out Value: Int16): Boolean;
begin
Value := Int16(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt16(const ValueName: String; out Value: Int16): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := Int16(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt16): Boolean;
begin
Value := UInt16(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt16(const KeyName,ValueName: String; out Value: UInt16): Boolean;
begin
Value := UInt16(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt16(const ValueName: String; out Value: UInt16): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := UInt16(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int32): Boolean;
begin
Value := Int32(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt32(const KeyName,ValueName: String; out Value: Int32): Boolean;
begin
Value := Int32(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt32(const ValueName: String; out Value: Int32): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := Int32(Temp);
end;
 
//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt32): Boolean;
begin
Value := UInt32(TryReadMacro(RootKey,KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt32(const KeyName,ValueName: String; out Value: UInt32): Boolean;
begin
Value := UInt32(TryReadMacro(KeyName,ValueName,Result));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt32(const ValueName: String; out Value: UInt32): Boolean;
var
  Temp: Integer;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Temp);
Value := UInt32(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Int64): Boolean;
begin
Result := TryReadMacro(RootKey,KeyName,ValueName,Value,SizeOf(Int64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt64(const KeyName,ValueName: String; out Value: Int64): Boolean;
begin
Result := TryReadMacro(KeyName,ValueName,Value,SizeOf(Int64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInt64(const ValueName: String; out Value: Int64): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value,SizeOf(Int64),vtQWord);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: UInt64): Boolean;
begin
Result := TryReadMacro(RootKey,KeyName,ValueName,Value,SizeOf(UInt64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt64(const KeyName,ValueName: String; out Value: UInt64): Boolean;
begin
Result := TryReadMacro(KeyName,ValueName,Value,SizeOf(UInt64),vtQWord);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadUInt64(const ValueName: String; out Value: UInt64): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value,SizeOf(UInt64),vtQWord);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Integer): Boolean;
begin
Value := TryReadMacro(RootKey,KeyName,ValueName,Result);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInteger(const KeyName,ValueName: String; out Value: Integer): Boolean;
begin
Value := TryReadMacro(KeyName,ValueName,Result);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadInteger(const ValueName: String; out Value: Integer): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Float32): Boolean;
begin
Result := TryReadMacro(RootKey,KeyName,ValueName,Value,SizeOf(Float32),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat32(const KeyName,ValueName: String; out Value: Float32): Boolean;
begin
Result := TryReadMacro(KeyName,ValueName,Value,SizeOf(Float32),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat32(const ValueName: String; out Value: Float32): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value,SizeOf(Float32),vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Float64): Boolean;
begin
Result := TryReadMacro(RootKey,KeyName,ValueName,Value,SizeOf(Float64),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat64(const KeyName,ValueName: String; out Value: Float64): Boolean;
begin
Result := TryReadMacro(KeyName,ValueName,Value,SizeOf(Float64),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat64(const ValueName: String; out Value: Float64): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value,SizeOf(Float64),vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Double): Boolean;
begin
Result := TryReadFloat64(RootKey,KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat(const KeyName,ValueName: String; out Value: Double): Boolean;
begin
Result := TryReadFloat64(KeyName,ValueName,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadFloat(const ValueName: String; out Value: Double): Boolean;
begin
Result := TryReadFloat64(ValueName,Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: Currency): Boolean;
begin
Result := TryReadMacro(RootKey,KeyName,ValueName,Value,SizeOf(Currency),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadCurrency(const KeyName,ValueName: String; out Value: Currency): Boolean;
begin
Result := TryReadMacro(KeyName,ValueName,Value,SizeOf(Currency),vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadCurrency(const ValueName: String; out Value: Currency): Boolean;
begin
Result := GetValueDataStat(GetWorkingKey(True),ValueName,Value,SizeOf(Currency),vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(RootKey,KeyName,ValueName,Double(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadDateTime(const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(KeyName,ValueName,Double(Value));
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadDateTime(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(RootKey,KeyName,ValueName,Double(Value));
Value := Int(Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadDate(const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(KeyName,ValueName,Double(Value));
Value := Int(Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadDate(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
Value := Int(Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(RootKey,KeyName,ValueName,Double(Value));
Value := Frac(Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadTime(const KeyName,ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(KeyName,ValueName,Double(Value));
Value := Frac(Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadTime(const ValueName: String; out Value: TDateTime): Boolean;
begin
Result := TryReadFloat64(ValueName,Double(Value));
Value := Frac(Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: String): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(RootKey,KeyName,ValueName,Temp,vtString);
If Result then
  Value := WideToStr(Temp);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadString(const KeyName,ValueName: String; out Value: String): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(KeyName,ValueName,Temp,vtString);
If Result then
  Value := WideToStr(Temp);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadString(const ValueName: String; out Value: String): Boolean;
var
  Temp: WideString;
begin
Result := GetValueDataOut(GetWorkingKey(True),ValueName,Temp,vtString);
If Result then
  Value := WideToStr(Temp);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Value: String; Expand: Boolean = False): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(RootKey,KeyName,ValueName,Temp,vtExpandString);
If Result then
  begin
    If Expand then
      Value := ExpandString(Temp)
    else
      Value := WideToStr(Temp);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadExpandString(const KeyName,ValueName: String; out Value: String; Expand: Boolean = False): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(KeyName,ValueName,Temp,vtExpandString);
If Result then
  begin
    If Expand then
      Value := ExpandString(Temp)
    else
      Value := WideToStr(Temp);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadExpandString(const ValueName: String; out Value: String; Expand: Boolean = False): Boolean;
var
  Temp: WideString;
begin
Result := GetValueDataOut(GetWorkingKey(True),ValueName,Temp,vtExpandString);
If Result then
  begin
    If Expand then
      Value := ExpandString(Temp)
    else
      Value := WideToStr(Temp);
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(RootKey,KeyName,ValueName,Temp,vtMultiString);
If Result then
  ParseMultiString(Temp,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMultiString(const KeyName,ValueName: String; Value: TStrings): Boolean;
var
  Temp: WideString;
begin
Result := TryReadMacroOut(KeyName,ValueName,Temp,vtMultiString);
If Result then
  ParseMultiString(Temp,Value);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadMultiString(const ValueName: String; Value: TStrings): Boolean;
var
  Temp: WideString;
begin
Result := GetValueDataOut(GetWorkingKey(True),ValueName,Temp,vtMultiString);
If Result then
  ParseMultiString(Temp,Value);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Buff; var Size: TMemSize): Boolean;
begin
Result := TryReadMacroExtBuff(RootKey,KeyName,ValueName,Buff,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryBuffer(const KeyName,ValueName: String; out Buff; var Size: TMemSize): Boolean;
begin
Result := TryReadMacroExtBuff(KeyName,ValueName,Buff,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryBuffer(const ValueName: String; out Buff; var Size: TMemSize): Boolean;
begin
Result := GetValueDataExtBuff(GetWorkingKey(True),ValueName,Buff,Size,vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean;
begin
Result := TryReadMacroExtBuff(RootKey,KeyName,ValueName,Memory^,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean;
begin
Result := TryReadMacroExtBuff(KeyName,ValueName,Memory^,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryMemory(const ValueName: String; Memory: Pointer; var Size: TMemSize): Boolean;
begin
Result := GetValueDataExtBuff(GetWorkingKey(True),ValueName,Memory^,Size,vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryMemoryOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean;
begin
Result := TryReadMacroOut(RootKey,KeyName,ValueName,Memory,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryMemoryOut(const KeyName,ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean;
begin
Result := TryReadMacroOut(KeyName,ValueName,Memory,Size,vtBinary);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryMemoryOut(const ValueName: String; out Memory: Pointer; out Size: TMemSize): Boolean;
begin
Result := GetValueDataOut(GetWorkingKey(True),ValueName,Memory,Size,vtBinary);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.TryReadBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream): Boolean;
var
  Buffer: Pointer;
  Size:   TMemSize;
begin
Result := TryReadMacroOut(RootKey,KeyName,ValueName,Buffer,Size,vtBinary);
If Result then
  begin
    Stream.WriteBuffer(Buffer^,LongInt(Size));
    FreeMem(Buffer,Size);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryStream(const KeyName,ValueName: String; Stream: TStream): Boolean;
var
  Buffer: Pointer;
  Size:   TMemSize;
begin
Result := TryReadMacroOut(KeyName,ValueName,Buffer,Size,vtBinary);
If Result then
  begin
    Stream.WriteBuffer(Buffer^,LongInt(Size));
    FreeMem(Buffer,Size);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.TryReadBinaryStream(const ValueName: String; Stream: TStream): Boolean;
var
  Buffer: Pointer;
  Size:   TMemSize;
begin
Result := GetValueDataOut(GetWorkingKey(True),ValueName,Buffer,Size,vtBinary);
If Result then
  begin
    Stream.WriteBuffer(Buffer^,LongInt(Size));
    FreeMem(Buffer,Size);
  end;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBoolDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Boolean): Boolean;
begin
If not TryReadBool(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBoolDef(const KeyName,ValueName: String; Default: Boolean): Boolean;
begin
If not TryReadBool(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBoolDef(const ValueName: String; Default: Boolean): Boolean;
begin
If not TryReadBool(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt8Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int8): Int8;
begin
If not TryReadInt8(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt8Def(const KeyName,ValueName: String; Default: Int8): Int8;
begin
If not TryReadInt8(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt8Def(const ValueName: String; Default: Int8): Int8;
begin
If not TryReadInt8(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt8Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt8): UInt8;
begin
If not TryReadUInt8(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt8Def(const KeyName,ValueName: String; Default: UInt8): UInt8;
begin
If not TryReadUInt8(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt8Def(const ValueName: String; Default: UInt8): UInt8;
begin
If not TryReadUInt8(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt16Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int16): Int16;
begin
If not TryReadInt16(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt16Def(const KeyName,ValueName: String; Default: Int16): Int16;
begin
If not TryReadInt16(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt16Def(const ValueName: String; Default: Int16): Int16;
begin
If not TryReadInt16(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt16Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt16): UInt16;
begin
If not TryReadUInt16(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt16Def(const KeyName,ValueName: String; Default: UInt16): UInt16;
begin
If not TryReadUInt16(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt16Def(const ValueName: String; Default: UInt16): UInt16;
begin
If not TryReadUInt16(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int32): Int32;
begin
If not TryReadInt32(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt32Def(const KeyName,ValueName: String; Default: Int32): Int32;
begin
If not TryReadInt32(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt32Def(const ValueName: String; Default: Int32): Int32;
begin
If not TryReadInt32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt32): UInt32;
begin
If not TryReadUInt32(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt32Def(const KeyName,ValueName: String; Default: UInt32): UInt32;
begin
If not TryReadUInt32(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt32Def(const ValueName: String; Default: UInt32): UInt32;
begin
If not TryReadUInt32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Int64): Int64;
begin
If not TryReadInt64(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt64Def(const KeyName,ValueName: String; Default: Int64): Int64;
begin
If not TryReadInt64(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt64Def(const ValueName: String; Default: Int64): Int64;
begin
If not TryReadInt64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: UInt64): UInt64;
begin
If not TryReadUInt64(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt64Def(const KeyName,ValueName: String; Default: UInt64): UInt64;
begin
If not TryReadUInt64(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt64Def(const ValueName: String; Default: UInt64): UInt64;
begin
If not TryReadUInt64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadIntegerDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Integer): Integer;
begin
If not TryReadInteger(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadIntegerDef(const KeyName,ValueName: String; Default: Integer): Integer;
begin
If not TryReadInteger(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadIntegerDef(const ValueName: String; Default: Integer): Integer;
begin
If not TryReadInteger(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat32Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Float32): Float32;
begin
If not TryReadFloat32(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat32Def(const KeyName,ValueName: String; Default: Float32): Float32;
begin
If not TryReadFloat32(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat32Def(const ValueName: String; Default: Float32): Float32;
begin
If not TryReadFloat32(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat64Def(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Float64): Float64;
begin
If not TryReadFloat64(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat64Def(const KeyName,ValueName: String; Default: Float64): Float64;
begin
If not TryReadFloat64(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat64Def(const ValueName: String; Default: Float64): Float64;
begin
If not TryReadFloat64(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloatDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Double): Double;
begin
If not TryReadFloat(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloatDef(const KeyName,ValueName: String; Default: Double): Double;
begin
If not TryReadFloat(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloatDef(const ValueName: String; Default: Double): Double;
begin
If not TryReadFloat(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadCurrencyDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: Currency): Currency;
begin
If not TryReadCurrency(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadCurrencyDef(const KeyName,ValueName: String; Default: Currency): Currency;
begin
If not TryReadCurrency(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadCurrencyDef(const ValueName: String; Default: Currency): Currency;
begin
If not TryReadCurrency(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateTimeDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDateTime(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateTimeDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDateTime(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateTimeDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDateTime(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDate(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDate(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadDate(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadTimeDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadTime(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadTimeDef(const KeyName,ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadTime(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadTimeDef(const ValueName: String; Default: TDateTime): TDateTime;
begin
If not TryReadTime(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadStringDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Default: String): String;
begin
If not TryReadString(RootKey,KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadStringDef(const KeyName,ValueName: String; const Default: String): String;
begin
If not TryReadString(KeyName,ValueName,Result) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadStringDef(const ValueName: String; const Default: String): String;
begin
If not TryReadString(ValueName,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadExpandStringDef(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; const Default: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(RootKey,KeyName,ValueName,Result,Expand) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadExpandStringDef(const KeyName,ValueName: String; const Default: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(KeyName,ValueName,Result,Expand) then
  Result := Default;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadExpandStringDef(const ValueName: String; const Default: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(ValueName,Result,Expand) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBool(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Boolean;
begin
If not TryReadBool(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBool: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBool(const KeyName,ValueName: String): Boolean;
begin
If not TryReadBool(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBool: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBool(const ValueName: String): Boolean;
begin
If not TryReadBool(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBool: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int8;
begin
If not TryReadInt8(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt8: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt8(const KeyName,ValueName: String): Int8;
begin
If not TryReadInt8(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt8: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt8(const ValueName: String): Int8;
begin
If not TryReadInt8(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt8: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt8(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt8;
begin
If not TryReadUInt8(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt8: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt8(const KeyName,ValueName: String): UInt8;
begin
If not TryReadUInt8(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt8: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt8(const ValueName: String): UInt8;
begin
If not TryReadUInt8(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt8: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int16;
begin
If not TryReadInt16(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt16: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt16(const KeyName,ValueName: String): Int16;
begin
If not TryReadInt16(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt16: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt16(const ValueName: String): Int16;
begin
If not TryReadInt16(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt16: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt16(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt16;
begin
If not TryReadUInt16(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt16: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt16(const KeyName,ValueName: String): UInt16;
begin
If not TryReadUInt16(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt16: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt16(const ValueName: String): UInt16;
begin
If not TryReadUInt16(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt16: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int32;
begin
If not TryReadInt32(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt32(const KeyName,ValueName: String): Int32;
begin
If not TryReadInt32(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt32(const ValueName: String): Int32;
begin
If not TryReadInt32(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt32: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt32;
begin
If not TryReadUInt32(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt32(const KeyName,ValueName: String): UInt32;
begin
If not TryReadUInt32(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt32(const ValueName: String): UInt32;
begin
If not TryReadUInt32(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt32: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Int64;
begin
If not TryReadInt64(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt64(const KeyName,ValueName: String): Int64;
begin
If not TryReadInt64(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInt64(const ValueName: String): Int64;
begin
If not TryReadInt64(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInt64: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadUInt64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): UInt64;
begin
If not TryReadUInt64(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt64(const KeyName,ValueName: String): UInt64;
begin
If not TryReadUInt64(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadUInt64(const ValueName: String): UInt64;
begin
If not TryReadUInt64(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadUInt64: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadInteger(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Integer;
begin
If not TryReadInteger(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInteger: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInteger(const KeyName,ValueName: String): Integer;
begin
If not TryReadInteger(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInteger: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadInteger(const ValueName: String): Integer;
begin
If not TryReadInteger(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadInteger: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat32(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Float32;
begin
If not TryReadFloat32(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat32(const KeyName,ValueName: String): Float32;
begin
If not TryReadFloat32(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat32: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat32(const ValueName: String): Float32;
begin
If not TryReadFloat32(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat32: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat64(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Float64;
begin
If not TryReadFloat64(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat64(const KeyName,ValueName: String): Float64;
begin
If not TryReadFloat64(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat64: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat64(const ValueName: String): Float64;
begin
If not TryReadFloat64(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat64: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadFloat(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Double;
begin
If not TryReadFloat(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat(const KeyName,ValueName: String): Double;
begin
If not TryReadFloat(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadFloat(const ValueName: String): Double;
begin
If not TryReadFloat(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadFloat: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadCurrency(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): Currency;
begin
If not TryReadCurrency(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadCurrency: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadCurrency(const KeyName,ValueName: String): Currency;
begin
If not TryReadCurrency(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadCurrency: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadCurrency(const ValueName: String): Currency;
begin
If not TryReadCurrency(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadCurrency: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDateTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime;
begin
If not TryReadDateTime(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDateTime: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateTime(const KeyName,ValueName: String): TDateTime;
begin
If not TryReadDateTime(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDateTime: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDateTime(const ValueName: String): TDateTime;
begin
If not TryReadDateTime(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDateTime: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadDate(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime;
begin
If not TryReadDate(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDate: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDate(const KeyName,ValueName: String): TDateTime;
begin
If not TryReadDate(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDate: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadDate(const ValueName: String): TDateTime;
begin
If not TryReadDate(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadDate: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadTime(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): TDateTime;
begin
If not TryReadTime(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadTime: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadTime(const KeyName,ValueName: String): TDateTime;
begin
If not TryReadTime(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadTime: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadTime(const ValueName: String): TDateTime;
begin
If not TryReadTime(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadTime: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String): String;
begin
If not TryReadString(RootKey,KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadString(const KeyName,ValueName: String): String;
begin
If not TryReadString(KeyName,ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadString(const ValueName: String): String;
begin
If not TryReadString(ValueName,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadString: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadExpandString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(RootKey,KeyName,ValueName,Result,Expand) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadExpandString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadExpandString(const KeyName,ValueName: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(KeyName,ValueName,Result,Expand) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadExpandString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadExpandString(const ValueName: String; Expand: Boolean = False): String;
begin
If not TryReadExpandString(ValueName,Result,Expand) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadExpandString: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.ReadMultiString(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Value: TStrings);
begin
If not TryReadMultiString(RootKey,KeyName,ValueName,Value) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadMultiString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.ReadMultiString(const KeyName,ValueName: String; Value: TStrings);
begin
If not TryReadMultiString(KeyName,ValueName,Value) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadMultiString: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.ReadMultiString(const ValueName: String; Value: TStrings);
begin
If not TryReadMultiString(ValueName,Value) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadMultiString: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBinaryBuffer(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Buff; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryBuffer(RootKey,KeyName,ValueName,Buff,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryBuffer: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryBuffer(const KeyName,ValueName: String; out Buff; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryBuffer(KeyName,ValueName,Buff,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryBuffer: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryBuffer(const ValueName: String; out Buff; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryBuffer(ValueName,Buff,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryBuffer: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBinaryMemory(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryMemory(RootKey,KeyName,ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryMemory(const KeyName,ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryMemory(KeyName,ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize;
begin
Result := Size;
If not TryReadBinaryMemory(ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

Function TRegistryEx.ReadBinaryMemoryOut(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; out Memory: Pointer): TMemSize;
begin
If not TryReadBinaryMemoryOut(RootKey,KeyName,ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryMemoryOut(const KeyName,ValueName: String; out Memory: Pointer): TMemSize;
begin
If not TryReadBinaryMemoryOut(KeyName,ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Function TRegistryEx.ReadBinaryMemoryOut(const ValueName: String; out Memory: Pointer): TMemSize;
begin
If not TryReadBinaryMemoryOut(ValueName,Memory,Result) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryMemory: Error reading value "%s".',[ValueName]);
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.ReadBinaryStream(RootKey: TRXPredefinedKey; const KeyName,ValueName: String; Stream: TStream);
begin
If not TryReadBinaryStream(RootKey,KeyName,ValueName,Stream) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryStream: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.ReadBinaryStream(const KeyName,ValueName: String; Stream: TStream);
begin
If not TryReadBinaryStream(KeyName,ValueName,Stream) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryStream: Error reading value "%s".',[ValueName]);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TRegistryEx.ReadBinaryStream(const ValueName: String; Stream: TStream);
begin
If not TryReadBinaryStream(ValueName,Stream) then
  raise ERXRegistryReadError.CreateFmt('TRegistryEx.ReadBinaryStream: Error reading value "%s".',[ValueName]);
end;

(*
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
*)


{===============================================================================
--------------------------------------------------------------------------------
                      Unit initialization and finalization
--------------------------------------------------------------------------------
===============================================================================}
var
  AdvApi32Handle: TDLULibraryHandle;

//------------------------------------------------------------------------------

procedure UnitInitialize;
begin
AdvApi32Handle := OpenAndCheckLibrary('advapi32.dll');
{$IFNDEF CPU64bit}
If IsWindowsVistaOrGreater or IsRunningUnderWoW64 then
{$ENDIF}
  begin
    RegQueryReflectionKey := GetAndCheckSymbolAddr(AdvApi32Handle,'RegQueryReflectionKey');
    RegEnableReflectionKey := GetAndCheckSymbolAddr(AdvApi32Handle,'RegEnableReflectionKey');
    RegDisableReflectionKey := GetAndCheckSymbolAddr(AdvApi32Handle,'RegDisableReflectionKey');
  end;
end;

//------------------------------------------------------------------------------

procedure UnitFinalize;
begin
CloseLibrary(AdvApi32Handle);
end;

//------------------------------------------------------------------------------

initialization
  UnitInitialize;

finalization
  UnitFinalize;

end.
