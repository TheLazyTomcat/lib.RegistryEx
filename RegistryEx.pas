unit RegistryEx;

interface

uses
  Windows, Classes,
  AuxTypes;

type
  TRXKeyAccessRight = (karDelete,karReadControl,karWriteDAC,karWriteOwner,
                       karCreateLink,karCreateSubKey,karEnumerateSubKeys,
                       karNotify,karQueryValue,karSetValue,karWoW64_32Key,
                       karWoW64_64Key);

  TRXKeyAccessRights = set of TRXKeyAccessRight;

const
  karExecute = [karNotify,karEnumerateSubKeys,karQueryValue,karReadControl];
  karRead    = karExecute;
  karWrite   = [karCreateSubKey,karSetValue,karReadControl];

  karStandardAccessRights = [karDelete,karReadControl,karWriteDAC,karWriteOwner];

  karAllAccess = karStandardAccessRights + [karQueryValue,karSetValue,
    karCreateSubKey,karEnumerateSubKeys,karNotify,karCreateLink];

type
  TRXRootKey = (rkClassesRoot,rkCurrentUser,rkLocalMachine,rkUsers,
                rkPerformanceData,rkPerformanceText,rkPerformanceNLSText,
                rkCurrentConfig,rkDynData,rkCurrentUserLocalSettings);

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

  TRXValueType = (rvtBinary,rvtDWord,rvtDWordLE,rvtDWordBE,rvtExpandString,rvtLink,
                  rvtMultiString,rvtNone,rvtQWord,rvtQWordLE,rvtString,rvtUnknown);

  TRXValueInfo = record
    ValueType:  TRXValueType;
    DataSize:   TMemSize;
  end;

  TRegistryEx = class(TObject)
  private
    fAccessRights:      TRXKeyAccessRights;
    fAccessRightsSys:   DWORD;
    fRootKey:           TRXRootKey;
    fRootKeyHandle:     HKEY;
    fCurrentKeyHandle:  HKEY;
    fCurrentKeyName:    String;
    fFlushOnClose:      Boolean;
    procedure SetAccessRights(Value: TRXKeyAccessRights);
    procedure SetAccessRightsSys(Value: DWORD);
    procedure SetRootKey(Value: TRXRootKey);
    procedure SetRootKeyHandle(Value: HKEY);
  protected
    class Function IsRelativeGetRectified(const KeyName: String; out RectifiedKeyName: String): Boolean; virtual;
    procedure SetCurrentKey(KeyHandle: HKEY; const KeyName: String); virtual;
    Function GetWorkingKey(Relative: Boolean): HKEY; virtual;
    {$message 'used only once, remove?'}
    Function OpenKeyInternal(const KeyName: String; AccessRights: DWORD): HKEY; virtual;

    procedure ChangingRootKey; virtual;

    procedure SetValueData(const ValueName: String; const Data; Size: TMemSize; ValueType: TRXValueType); overload; virtual;
    procedure SetValueData(const ValueName: String; Data: Integer); overload; virtual;
    Function GetValueData(const ValueName: String; out Data; Size: TMemSize; ValueType: TRXValueType): Boolean; overload; virtual;
    Function GetValueData(const ValueName: String; out Data: Integer): Boolean; overload; virtual;
  public
    class Function RegistryQuotaAllowed: UInt32; virtual;
    class Function RegistryQuotaUsed: UInt32; virtual;
      
    constructor Create(AccessRights: TRXKeyAccessRights = karAllAccess); overload;
    constructor Create(RootKey: TRXRootKey; AccessRights: TRXKeyAccessRights = karAllAccess); overload;
    destructor Destroy; override;

    // global keys access (does not depend on open key)
    Function KeyExists(const KeyName: String): Boolean; virtual;
    Function CreateKey(const KeyName: String): Boolean; virtual;
    Function DeleteKey(const KeyName: String): Boolean; virtual;

    // current key access
    Function OpenKey(const KeyName: String; CanCreate: Boolean): Boolean; virtual;
    Function OpenKeyReadOnly(const KeyName: String): Boolean; virtual;
    Function GetKeyInfo(out KeyInfo: TRXKeyInfo): Boolean; virtual;
    procedure GetSubKeys(SubKeys: TStrings); virtual;
    Function HasSubKeys: Boolean; virtual;
    procedure FlushKey; virtual;
    procedure CloseKey; virtual;

    Function ValueExists(const ValueName: String): Boolean; virtual;
    procedure GetValues(Values: TStrings); virtual;
    Function GetValueInfo(const ValueName: String; out ValueInfo: TRXValueInfo): Boolean; virtual;
    Function GetValueType(const ValueName: String): TRXValueType; virtual;
    Function GetValueDataSize(const ValueName: String): TMemSize; virtual;
    Function DeleteValue(const ValueName: String): Boolean; virtual;

    procedure DeleteSubKeys; virtual;
    procedure DeleteValues; virtual;
    procedure DeleteContent; virtual;

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

    procedure WriteDateTime(const ValueName: String; Value: TDateTime); virtual;
    procedure WriteDate(const ValueName: String; Value: TDateTime); virtual;
    procedure WriteTime(const ValueName: String; Value: TDateTime); virtual;

    procedure WriteString(const ValueName: String; const Value: String); virtual;
    procedure WriteExpandString(const ValueName: String; const Value: String); virtual;

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

    Function ReadBinaryBuffer(const ValueName: String; out Buff; Size: TMemSize): TMemSize; virtual;
    Function ReadBinaryMemory(const ValueName: String; Memory: Pointer; Size: TMemSize): TMemSize; virtual;
    Function ReadBinaryStream(const ValueName: String; Stream: TStream): TMemSize; virtual;

    property AccessRights: TRXKeyAccessRights read fAccessRights write SetAccessRights;
    property AccessRightsSys: DWORD read fAccessRightsSys write SetAccessRightsSys;
    property RootKey: TRXRootKey read fRootKey write SetRootKey;
    property RootKeyHandle: HKEY read fRootKeyHandle write SetRootKeyHandle;
    property CurrentKeyHandle: HKEY read fCurrentKeyHandle;
    property CurrentKeyName: String read fCurrentKeyName;
    property FlushOnClose: Boolean read fFlushOnClose write fFlushOnClose;
  end;

implementation

uses
  SysUtils,
  BitOps, AuxExceptions, StrRect;

type
  LSTATUS = Int32;
  LPBYTE  = ^Byte;

const
  REG_PATH_DLEIMITER = '\';

  KEY_WOW64_32KEY = DWORD($00000200);
  KEY_WOW64_64KEY = DWORD($00000100);

  HKEY_PERFORMANCE_TEXT            = HKEY($80000050);
  HKEY_PERFORMANCE_NLSTEXT         = HKEY($80000060);
  HKEY_CURRENT_USER_LOCAL_SETTINGS = HKEY($80000007);

  REG_QWORD               = 11;
  REG_QWORD_LITTLE_ENDIAN = 11;

Function SHDeleteKeyW(hkey: HKEY; pszSubKey: LPCWSTR): LSTATUS; stdcall; external 'Shlwapi.dll';

Function GetSystemRegistryQuota(pdwQuotaAllowed: PDWORD; pdwQuotaUsed: PDWORD): BOOL; stdcall; external 'kernel32.dll';

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
      raise Exception.CreateFmt('FileTimeToDateTime: Unable to convert to system time (0x%.8x).',[GetLastError]);
  end
else raise Exception.CreateFmt('FileTimeToDateTime: Unable to convert to local time (0x%.8x).',[GetLastError]);
end;

//------------------------------------------------------------------------------

Function EncodeValueType(RegValueType: DWORD): TRXValueType;
begin
case RegValueType of
  REG_BINARY:               Result := rvtBinary;
  REG_DWORD:                Result := rvtDWord;
//REG_DWORD_LITTLE_ENDIAN:  Result := rvtDWordLE; // the same as REG_DWORD, duplicit label
  REG_DWORD_BIG_ENDIAN:     Result := rvtDWordBE;
  REG_EXPAND_SZ:            Result := rvtExpandString;
  REG_LINK:                 Result := rvtLink;
  REG_MULTI_SZ:             Result := rvtMultiString;
  REG_NONE:                 Result := rvtNone;
  REG_QWORD:                Result := rvtQWord;
//REG_QWORD_LITTLE_ENDIAN:  Result := rvtQWordLE; // the same as REG_QWORD, duplicit label
  REG_SZ:                   Result := rvtString;
else
  Result := rvtUnknown;
end;
end;

//------------------------------------------------------------------------------

Function DecodeValueType(ValueType: TRXValueType): DWORD;
begin
case ValueType of
  rvtBinary:        Result := REG_BINARY;
  rvtDWord:         Result := REG_DWORD;
  rvtDWordLE:       Result := REG_DWORD_LITTLE_ENDIAN;
  rvtDWordBE:       Result := REG_DWORD_BIG_ENDIAN;
  rvtExpandString:  Result := REG_EXPAND_SZ;
  rvtLink:          Result := REG_LINK;
  rvtMultiString:   Result := REG_MULTI_SZ;
  rvtNone:          Result := REG_NONE;
  rvtQWord:         Result := REG_QWORD;
  rvtQWordLE:       Result := REG_QWORD_LITTLE_ENDIAN;
  rvtString:        Result := REG_SZ;
else
  Result := REG_NONE;
end;
end;

//==============================================================================

procedure TRegistryEx.SetAccessRights(Value: TRXKeyAccessRights);
begin
If Value <> fAccessRights then
  begin
    fAccessRights := Value;
    fAccessRightsSys := 0;
    If karDelete in fAccessRights then
      SetFlagValue(fAccessRightsSys,_DELETE);
    If karReadControl in fAccessRights then
      SetFlagValue(fAccessRightsSys,READ_CONTROL);
    If karWriteDAC in fAccessRights then
      SetFlagValue(fAccessRightsSys,WRITE_DAC);
    If karWriteOwner in fAccessRights then
      SetFlagValue(fAccessRightsSys,WRITE_OWNER);
    If karCreateLink in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_CREATE_LINK);
    If karCreateSubKey in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_CREATE_SUB_KEY);
    If karEnumerateSubKeys in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_ENUMERATE_SUB_KEYS);
    If karExecute <= fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_EXECUTE);
    If karNotify in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_NOTIFY);
    If karQueryValue in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_QUERY_VALUE);
    If karRead <= fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_READ);
    If karSetValue in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_SET_VALUE);
    If karWoW64_32Key in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_WOW64_32KEY);
    If karWoW64_64Key in fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_WOW64_64KEY);
    If karWrite <= fAccessRights then
      SetFlagValue(fAccessRightsSys,KEY_WRITE);
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetAccessRightsSys(Value: DWORD);

  procedure SetRights(Flag: TRXKeyAccessRight; Value: Boolean); overload;
  begin
    If Value then
      Include(fAccessRights,Flag);
  end;

  procedure SetRights(Flags: TRXKeyAccessRights; Value: Boolean); overload;
  begin
    If Value then
      fAccessRights := fAccessRights + Flags;
  end;

begin
If Value <> fAccessRightsSys then
  begin
    fAccessRights := [];
    fAccessRightsSys := Value;
    SetRights(karDelete,GetFlagState(fAccessRightsSys,_DELETE,True));
    SetRights(karReadControl,GetFlagState(fAccessRightsSys,READ_CONTROL,True));
    SetRights(karWriteDAC,GetFlagState(fAccessRightsSys,WRITE_DAC,True));
    SetRights(karWriteOwner,GetFlagState(fAccessRightsSys,WRITE_OWNER,True));
    SetRights(karCreateLink,GetFlagState(fAccessRightsSys,KEY_CREATE_LINK,True));
    SetRights(karCreateSubKey,GetFlagState(fAccessRightsSys,KEY_CREATE_SUB_KEY,True));
    SetRights(karEnumerateSubKeys,GetFlagState(fAccessRightsSys,KEY_ENUMERATE_SUB_KEYS,True));
    SetRights(karExecute,GetFlagState(fAccessRightsSys,KEY_EXECUTE,True));
    SetRights(karNotify,GetFlagState(fAccessRightsSys,KEY_NOTIFY,True));
    SetRights(karQueryValue,GetFlagState(fAccessRightsSys,KEY_QUERY_VALUE,True));
    SetRights(karRead,GetFlagState(fAccessRightsSys,KEY_READ,True));
    SetRights(karSetValue,GetFlagState(fAccessRightsSys,KEY_SET_VALUE,True));
    SetRights(karWoW64_32Key,GetFlagState(fAccessRightsSys,KEY_WOW64_32KEY,True));
    SetRights(karWoW64_64Key,GetFlagState(fAccessRightsSys,KEY_WOW64_64KEY,True));
    SetRights(karWrite,GetFlagState(fAccessRightsSys,KEY_WRITE,True));
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetRootKey(Value: TRXRootKey);
begin
If Value <> fRootKey then
  begin
    ChangingRootKey;
    fRootKey := Value;
    case Value of
      rkClassesRoot:              fRootKeyHandle := HKEY_CLASSES_ROOT;
      rkCurrentUser:              fRootKeyHandle := HKEY_CURRENT_USER;
      rkLocalMachine:             fRootKeyHandle := HKEY_LOCAL_MACHINE;
      rkUsers:                    fRootKeyHandle := HKEY_USERS;
      rkPerformanceData:          fRootKeyHandle := HKEY_PERFORMANCE_DATA;
      rkPerformanceText:          fRootKeyHandle := HKEY_PERFORMANCE_TEXT;
      rkPerformanceNLSText:       fRootKeyHandle := HKEY_PERFORMANCE_NLSTEXT;
      rkCurrentConfig:            fRootKeyHandle := HKEY_CURRENT_CONFIG;
      rkDynData:                  fRootKeyHandle := HKEY_DYN_DATA;
      rkCurrentUserLocalSettings: fRootKeyHandle := HKEY_CURRENT_USER_LOCAL_SETTINGS;
    else
      raise Exception.CreateFmt('TRegistryEx.SetRootKey: Invalid root key (%d).',[Ord(Value)]);
    end;
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetRootKeyHandle(Value: HKEY);
begin
If Value <> fRootKeyHandle then
  begin
    ChangingRootKey;
    fRootKeyHandle := Value;
    case Value of
      HKEY_CLASSES_ROOT:                fRootKey := rkClassesRoot;
      HKEY_CURRENT_USER:                fRootKey := rkCurrentUser;
      HKEY_LOCAL_MACHINE:               fRootKey := rkLocalMachine;
      HKEY_USERS:                       fRootKey := rkUsers;
      HKEY_PERFORMANCE_DATA:            fRootKey := rkPerformanceData;
      HKEY_PERFORMANCE_TEXT:            fRootKey := rkPerformanceText;
      HKEY_PERFORMANCE_NLSTEXT:         fRootKey := rkPerformanceNLSText;
      HKEY_CURRENT_CONFIG:              fRootKey := rkCurrentConfig;
      HKEY_DYN_DATA:                    fRootKey := rkDynData;
      HKEY_CURRENT_USER_LOCAL_SETTINGS: fRootKey := rkCurrentUserLocalSettings;
    else
      raise Exception.CreateFmt('TRegistryEx.SetRootKeyHandle: Invalid root key (%.8x).',[Value]);
    end;
  end;
end;

//==============================================================================

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

end.
