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

  TRXValueType = (rvtBinary,rvtDWord,rvtDWordLE = rvtDWord,rvtDWordBE,
                  rvtExpandString,rvtLink,rvtMultiString,rvtNone,rvtQWord,
                  rvtQWordLE = rvtQWord,rvtString,rvtUnknown);

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
//REG_DWORD_LITTLE_ENDIAN:  Result := rvtDWordLE;       // the same as REG_DWORD
  REG_DWORD_BIG_ENDIAN:     Result := rvtDWordBE;
  REG_EXPAND_SZ:            Result := rvtExpandString;
  REG_LINK:                 Result := rvtLink;
  REG_MULTI_SZ:             Result := rvtMultiString;
  REG_NONE:                 Result := rvtNone;
  REG_QWORD:                Result := rvtQWord;
//REG_QWORD_LITTLE_ENDIAN:  Result := rvtQWordLE;       // the same as REG_QWORD
  REG_SZ:                   Result := rvtString;
else
  Result := rvtUnknown;
end;
end;

//==============================================================================

procedure TRegistryEx.SetAccessRights(Value: TRXKeyAccessRights);
begin
If Value <> fAccessRights then
  begin
    fAccessRights := Value;
    fAccessRightsSys := 0;
    // resolve individual flags
    SetFlagStateValue(fAccessRightsSys,_DELETE,karDelete in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,READ_CONTROL,karReadControl in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,WRITE_DAC,karWriteDAC in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,WRITE_OWNER,karWriteOwner in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_CREATE_LINK,karCreateLink in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_CREATE_SUB_KEY,karCreateSubKey in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_ENUMERATE_SUB_KEYS,karEnumerateSubKeys in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_EXECUTE,karExecute <= fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_NOTIFY,karNotify in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_QUERY_VALUE,karQueryValue in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_READ,karRead <= fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_SET_VALUE,karSetValue in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_WOW64_32KEY,karWoW64_32Key in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_WOW64_64KEY,karWoW64_64Key in fAccessRights);
    SetFlagStateValue(fAccessRightsSys,KEY_WRITE,karWrite <= fAccessRights);
  end;
end;

//------------------------------------------------------------------------------

procedure TRegistryEx.SetAccessRightsSys(Value: DWORD);

  procedure SetRights(Flag: TRXKeyAccessRight; Value: Boolean); overload;
  begin
    If Value then
      Include(fAccessRights,Flag)
    else
      Exclude(fAccessRights,Flag);
  end;

  procedure SetRights(Flags: TRXKeyAccessRights; Value: Boolean); overload;
  begin
    If Value then
      fAccessRights := fAccessRights + Flags
    else
      fAccessRights := fAccessRights - Flags;
  end;

begin
If Value <> fAccessRightsSys then
  begin
    fAccessRights := [];
    fAccessRightsSys := Value;
    // resolve individual flags
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
      begin
        OpenKeyReadOnly := True;
        SetAccessRightsSys(AccessRights);
      end;
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

end.
