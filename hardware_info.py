#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сведения об оборудовании компьютера (Windows 10/11 и Linux).

Собирает подробную информацию обо всём установленном железе: система и корпус,
BIOS/UEFI, материнская плата, процессор, оперативная память (по модулям),
видеокарты, мониторы, накопители и разделы, сетевые и звуковые адаптеры,
устройства ввода, камеры, Bluetooth, USB, батарея, принтеры, оптические
приводы, TPM, а также полный список устройств из Диспетчера устройств
с версиями драйверов и отдельным списком неисправных устройств.

Сторонние библиотеки не нужны. В Windows данные берутся из WMI/CIM через
встроенный PowerShell, а также из реестра и WinAPI (через ctypes). В Linux —
напрямую из ядра (/sys, /proc), таблиц прошивки SMBIOS и NVMe-контроллера.

Раздел «Проверка состояния» подсказывает, не б/у ли железо: износ батареи,
наработка и объём записанного на диск, ошибки SMART, память и устройства.

Примеры запуска:
    python hardware_info.py              отчёт в консоль + файлы TXT, HTML, JSON
    python hardware_info.py --open       то же и сразу открыть HTML-отчёт
    python hardware_info.py --elevate    с правами администратора (в Linux — root через sudo)
    python hardware_info.py --anon       скрыть серийные номера, MAC, IP и т. п.
    python hardware_info.py --help       все параметры
"""

from __future__ import annotations

import argparse
import codecs
import ctypes
import datetime as dt
import getpass
import gzip
import html
import json
import math
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict

try:
    import winreg
except ImportError:  # не Windows — работает только режим --load-raw
    winreg = None

VERSION = "2.1"
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # без мелькающего окна консоли
HIDDEN = "‹скрыто›"


# ---------------------------------------------------------------------------
# Сбор данных через PowerShell (WMI/CIM)
# ---------------------------------------------------------------------------

# Скрипт передаётся PowerShell через stdin и выполняется целиком как scriptblock.
# Он только читает данные и ничего не меняет в системе. Результат — JSON,
# в котором все не-ASCII символы экранированы (\uXXXX), поэтому кодировка
# консоли на результат не влияет. Сам скрипт должен оставаться чисто ASCII.
PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$r = [ordered]@{}
$err = [ordered]@{}

function Conv($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [datetime]) { return $v.ToString('yyyy-MM-ddTHH:mm:ss') }
    if ($v -is [char]) { return [string]$v }
    if ($v -is [array]) { return ,$v }
    return $v
}

function Q {
    param([string]$Key, [string]$Ns, [string]$Cls, [string[]]$Props, [string]$Filter = '')
    try {
        $p = @{ Namespace = $Ns; ClassName = $Cls; OperationTimeoutSec = 60; ErrorAction = 'Stop' }
        if ($Filter) { $p['Filter'] = $Filter }
        $list = New-Object System.Collections.ArrayList
        foreach ($i in @(Get-CimInstance @p)) {
            $o = [ordered]@{}
            foreach ($n in $Props) { $o[$n] = Conv $i.$n }
            [void]$list.Add($o)
        }
        $r[$Key] = $list
    } catch {
        $err[$Key] = $_.Exception.Message
    }
}

$cim = 'root/cimv2'
$wmi = 'root/wmi'
$stor = 'root/Microsoft/Windows/Storage'

Q 'system' $cim 'Win32_ComputerSystem' @('Name','Manufacturer','Model','SystemFamily','SystemSKUNumber','SystemType','PCSystemType','TotalPhysicalMemory','NumberOfProcessors','NumberOfLogicalProcessors','HypervisorPresent','Domain','PartOfDomain','Workgroup','UserName')
Q 'product' $cim 'Win32_ComputerSystemProduct' @('Vendor','Name','Version','IdentifyingNumber','UUID')
Q 'enclosure' $cim 'Win32_SystemEnclosure' @('Manufacturer','ChassisTypes','SerialNumber','SMBIOSAssetTag')
Q 'os' $cim 'Win32_OperatingSystem' @('Caption','Version','BuildNumber','OSArchitecture','InstallDate','LastBootUpTime','RegisteredUser','Organization','TotalVisibleMemorySize','FreePhysicalMemory')
Q 'bios' $cim 'Win32_BIOS' @('Manufacturer','Name','SMBIOSBIOSVersion','Version','ReleaseDate','SerialNumber','SMBIOSMajorVersion','SMBIOSMinorVersion','EmbeddedControllerMajorVersion','EmbeddedControllerMinorVersion')
Q 'baseboard' $cim 'Win32_BaseBoard' @('Manufacturer','Product','Version','SerialNumber')
Q 'cpu' $cim 'Win32_Processor' @('Name','Manufacturer','Caption','NumberOfCores','NumberOfEnabledCore','NumberOfLogicalProcessors','MaxClockSpeed','CurrentClockSpeed','L2CacheSize','L3CacheSize','SocketDesignation','Architecture','AddressWidth','ProcessorId','VirtualizationFirmwareEnabled','SecondLevelAddressTranslationExtensions')
Q 'memory' $cim 'Win32_PhysicalMemory' @('BankLabel','DeviceLocator','Capacity','Speed','ConfiguredClockSpeed','Manufacturer','PartNumber','SerialNumber','SMBIOSMemoryType','MemoryType','FormFactor','DataWidth','TotalWidth','ConfiguredVoltage')
Q 'memarray' $cim 'Win32_PhysicalMemoryArray' @('MaxCapacity','MaxCapacityEx','MemoryDevices','Use','MemoryErrorCorrection')
Q 'gpu' $cim 'Win32_VideoController' @('Name','AdapterCompatibility','AdapterRAM','DriverVersion','DriverDate','VideoProcessor','CurrentHorizontalResolution','CurrentVerticalResolution','CurrentRefreshRate','CurrentBitsPerPixel','PNPDeviceID','Status')
Q 'monitor_id' $wmi 'WmiMonitorID' @('InstanceName','Active','ManufacturerName','ProductCodeID','SerialNumberID','UserFriendlyName','YearOfManufacture','WeekOfManufacture')
Q 'monitor_params' $wmi 'WmiMonitorBasicDisplayParams' @('InstanceName','MaxHorizontalImageSize','MaxVerticalImageSize','VideoInputType')
Q 'monitor_conn' $wmi 'WmiMonitorConnectionParams' @('InstanceName','VideoOutputTechnology')
Q 'physdisk' $stor 'MSFT_PhysicalDisk' @('DeviceId','FriendlyName','Model','SerialNumber','MediaType','BusType','Size','HealthStatus','SpindleSpeed','FirmwareVersion')
Q 'diskdrive' $cim 'Win32_DiskDrive' @('Index','Model','Size','InterfaceType','MediaType','SerialNumber','FirmwareRevision','Partitions','Status')
Q 'partition' $stor 'MSFT_Partition' @('DiskNumber','PartitionNumber','DriveLetter','Size','GptType','MbrType','IsBoot','IsSystem')
Q 'logicaldisk' $cim 'Win32_LogicalDisk' @('DeviceID','VolumeName','FileSystem','Size','FreeSpace','DriveType','ProviderName')
Q 'netadapter' $cim 'Win32_NetworkAdapter' @('Index','Name','Manufacturer','MACAddress','Speed','NetConnectionID','NetConnectionStatus','AdapterType','PNPDeviceID') 'PhysicalAdapter = TRUE'
Q 'netconfig' $cim 'Win32_NetworkAdapterConfiguration' @('Index','IPAddress','DefaultIPGateway','DNSServerSearchOrder','DHCPEnabled') 'IPEnabled = TRUE'
Q 'sound' $cim 'Win32_SoundDevice' @('Name','Manufacturer','Status','PNPDeviceID')
Q 'keyboard' $cim 'Win32_Keyboard' @('Name','Description','PNPDeviceID')
Q 'mouse' $cim 'Win32_PointingDevice' @('Name','Manufacturer','PNPDeviceID')
Q 'usbctrl' $cim 'Win32_USBController' @('Name','Manufacturer','PNPDeviceID')
Q 'battery' $cim 'Win32_Battery' @('Name','DeviceID','EstimatedChargeRemaining','EstimatedRunTime','BatteryStatus','Chemistry','DesignCapacity','FullChargeCapacity')
Q 'battery_static' $wmi 'BatteryStaticData' @('InstanceName','DeviceName','ManufactureName','SerialNumber','DesignedCapacity')
Q 'battery_full' $wmi 'BatteryFullChargedCapacity' @('InstanceName','FullChargedCapacity')
Q 'battery_cycles' $wmi 'BatteryCycleCount' @('InstanceName','CycleCount')
Q 'printer' $cim 'Win32_Printer' @('Name','DriverName','PortName','Default','Network','WorkOffline')
Q 'cdrom' $cim 'Win32_CDROMDrive' @('Name','Drive','Manufacturer')
Q 'tpm' 'root/cimv2/Security/MicrosoftTpm' 'Win32_Tpm' @('IsActivated_InitialValue','IsEnabled_InitialValue','IsOwned_InitialValue','ManufacturerIdTxt','ManufacturerVersion','SpecVersion')
Q 'pnp' $cim 'Win32_PnPEntity' @('Name','PNPClass','Manufacturer','Status','ConfigManagerErrorCode','PNPDeviceID','Present')
Q 'drivers' $cim 'Win32_PnPSignedDriver' @('DeviceID','DriverVersion','DriverDate','DriverProviderName')

# Disk reliability counters (temperature, wear, power-on hours) require administrator rights.
try {
    $list = New-Object System.Collections.ArrayList
    foreach ($d in @(Get-CimInstance -Namespace $stor -ClassName 'MSFT_PhysicalDisk' -ErrorAction Stop)) {
        foreach ($x in @(Get-CimAssociatedInstance -InputObject $d -ResultClassName 'MSFT_StorageReliabilityCounter' -ErrorAction Stop)) {
            if ($null -eq $x) { continue }
            $o = [ordered]@{ DeviceId = [string]$d.DeviceId }
            foreach ($n in @('Temperature','TemperatureMax','Wear','PowerOnHours','ReadErrorsUncorrected','WriteErrorsUncorrected','StartStopCycleCount')) { $o[$n] = Conv $x.$n }
            [void]$list.Add($o)
        }
    }
    $r['disk_health'] = $list
} catch {
    $err['disk_health'] = $_.Exception.Message
}

$payload = [ordered]@{ data = $r; errors = $err; ps_version = $PSVersionTable.PSVersion.ToString() }
$json = ConvertTo-Json -InputObject $payload -Depth 8 -Compress
$json = [regex]::Replace($json, '[^\u0000-\u007F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
[Console]::Out.Write('<<<HWINFO-JSON>>>' + $json + '<<<HWINFO-END>>>')
[Console]::Out.Flush()
"""


class CollectError(RuntimeError):
    pass


def find_powershell():
    for name in ("powershell.exe", "pwsh.exe", "powershell", "pwsh"):
        path = shutil.which(name)
        if path:
            return path
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.exists(path) else None


def decode_console(data):
    for enc in ("oem", "utf-8"):
        try:
            codecs.lookup(enc)
            return data.decode(enc, errors="replace")
        except LookupError:
            continue
    return data.decode("latin-1")


def collect_wmi(timeout=300):
    ps = find_powershell()
    if not ps:
        raise CollectError("Не найден PowerShell (powershell.exe). Он входит в состав Windows 7 SP1 и новее.")
    cmd = [ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
           "$s = [Console]::In.ReadToEnd(); & ([scriptblock]::Create($s))"]
    try:
        proc = subprocess.run(cmd, input=PS_SCRIPT.encode("ascii"), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise CollectError(f"PowerShell не ответил за {timeout} с.")
    except OSError as exc:
        raise CollectError(f"Не удалось запустить PowerShell: {exc}")
    out = proc.stdout.decode("utf-8", errors="replace")
    match = re.search(r"<<<HWINFO-JSON>>>(.*?)<<<HWINFO-END>>>", out, re.S)
    if not match:
        details = (decode_console(proc.stderr).strip() or out.strip())[-3000:]
        raise CollectError("PowerShell не вернул данные.\n" + details)
    try:
        return json.loads(match.group(1))
    except ValueError as exc:
        raise CollectError(f"Не удалось разобрать ответ PowerShell: {exc}")


# ---------------------------------------------------------------------------
# Сбор данных из реестра и WinAPI
# ---------------------------------------------------------------------------

GPU_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"


def is_admin():
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _reg_open(path):
    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, flags)


def reg_value(path, name):
    if winreg is None:
        return None
    try:
        with _reg_open(path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def reg_subkeys(path):
    if winreg is None:
        return []
    names = []
    try:
        with _reg_open(path) as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names


def _reg_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and value:
        return int.from_bytes(bytes(value[:8]), "little")
    return None


def _reg_str(value):
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-16-le").strip("\x00 ")
        except UnicodeDecodeError:
            return None
    return value if isinstance(value, str) else None


def firmware_type():
    """Режим загрузки: UEFI или Legacy BIOS (WinAPI GetFirmwareType)."""
    try:
        value = ctypes.c_uint(0)
        if ctypes.windll.kernel32.GetFirmwareType(ctypes.byref(value)):
            return {1: "Legacy BIOS", 2: "UEFI"}.get(value.value)
    except Exception:
        pass
    return None


def gpu_registry():
    """Точный объём видеопамяти из реестра (WMI ограничивает его 4 ГБ)."""
    result = []
    for sub in reg_subkeys(GPU_CLASS_KEY):
        if not sub.isdigit():
            continue
        path = GPU_CLASS_KEY + "\\" + sub
        size = _reg_int(reg_value(path, "HardwareInformation.qwMemorySize"))
        if not size:
            size = _reg_int(reg_value(path, "HardwareInformation.MemorySize"))
        result.append({
            "name": reg_value(path, "DriverDesc"),
            "matching_id": reg_value(path, "MatchingDeviceId"),
            "memory": size,
            "chip": _reg_str(reg_value(path, "HardwareInformation.ChipType")),
            "bios": _reg_str(reg_value(path, "HardwareInformation.BiosString")),
        })
    return result


def read_edids():
    """EDID всех мониторов, когда-либо подключавшихся к компьютеру."""
    base = r"SYSTEM\CurrentControlSet\Enum\DISPLAY"
    result = {}
    for model in reg_subkeys(base):
        for inst in reg_subkeys(base + "\\" + model):
            edid = reg_value(f"{base}\\{model}\\{inst}\\Device Parameters", "EDID")
            if isinstance(edid, (bytes, bytearray)) and len(edid) >= 128:
                result[f"DISPLAY\\{model}\\{inst}".upper()] = bytes(edid).hex()
    return result


def interface_to_instance(path):
    """\\\\?\\DISPLAY#GSM5B7F#5&2a1b&0&UID4352#{guid} -> DISPLAY\\GSM5B7F\\5&2A1B&0&UID4352"""
    if not path:
        return None
    s = path[4:] if path.startswith("\\\\?\\") else path
    parts = s.split("#")
    if len(parts) < 3:
        return None
    return "\\".join(parts[:3]).upper()


def display_modes():
    """Текущие режимы активных мониторов (разрешение, частота, глубина цвета)."""
    user32 = ctypes.windll.user32
    wchar, dword, word, short, long_ = (ctypes.c_wchar, ctypes.c_uint32, ctypes.c_uint16,
                                        ctypes.c_int16, ctypes.c_int32)

    class DISPLAY_DEVICEW(ctypes.Structure):
        _fields_ = [("cb", dword), ("DeviceName", wchar * 32), ("DeviceString", wchar * 128),
                    ("StateFlags", dword), ("DeviceID", wchar * 128), ("DeviceKey", wchar * 128)]

    class DEVMODEW(ctypes.Structure):
        _fields_ = [("dmDeviceName", wchar * 32), ("dmSpecVersion", word), ("dmDriverVersion", word),
                    ("dmSize", word), ("dmDriverExtra", word), ("dmFields", dword),
                    ("dmPositionX", long_), ("dmPositionY", long_), ("dmDisplayOrientation", dword),
                    ("dmDisplayFixedOutput", dword), ("dmColor", short), ("dmDuplex", short),
                    ("dmYResolution", short), ("dmTTOption", short), ("dmCollate", short),
                    ("dmFormName", wchar * 32), ("dmLogPixels", word), ("dmBitsPerPel", dword),
                    ("dmPelsWidth", dword), ("dmPelsHeight", dword), ("dmDisplayFlags", dword),
                    ("dmDisplayFrequency", dword), ("dmICMMethod", dword), ("dmICMIntent", dword),
                    ("dmMediaType", dword), ("dmDitherType", dword), ("dmReserved1", dword),
                    ("dmReserved2", dword), ("dmPanningWidth", dword), ("dmPanningHeight", dword)]

    user32.EnumDisplayDevicesW.argtypes = [ctypes.c_wchar_p, dword, ctypes.POINTER(DISPLAY_DEVICEW), dword]
    user32.EnumDisplaySettingsW.argtypes = [ctypes.c_wchar_p, dword, ctypes.POINTER(DEVMODEW)]

    ACTIVE, PRIMARY, ENUM_CURRENT, GET_INTERFACE_NAME = 0x1, 0x4, 0xFFFFFFFF, 0x1
    result = []
    i = 0
    while True:
        adapter = DISPLAY_DEVICEW()
        adapter.cb = ctypes.sizeof(adapter)
        if not user32.EnumDisplayDevicesW(None, i, ctypes.byref(adapter), 0):
            break
        i += 1
        if not adapter.StateFlags & ACTIVE:
            continue
        mode = DEVMODEW()
        mode.dmSize = ctypes.sizeof(mode)
        if not user32.EnumDisplaySettingsW(adapter.DeviceName, ENUM_CURRENT, ctypes.byref(mode)):
            continue
        entry = {
            "device": adapter.DeviceName, "adapter": adapter.DeviceString,
            "primary": bool(adapter.StateFlags & PRIMARY),
            "width": mode.dmPelsWidth, "height": mode.dmPelsHeight,
            "frequency": mode.dmDisplayFrequency, "bpp": mode.dmBitsPerPel,
        }
        j = 0
        found = False
        while True:
            mon = DISPLAY_DEVICEW()
            mon.cb = ctypes.sizeof(mon)
            if not user32.EnumDisplayDevicesW(adapter.DeviceName, j, ctypes.byref(mon), GET_INTERFACE_NAME):
                break
            j += 1
            if mon.StateFlags & ACTIVE:
                result.append(dict(entry, instance=interface_to_instance(mon.DeviceID), monitor=mon.DeviceString))
                found = True
        if not found:
            result.append(dict(entry, instance=None, monitor=None))
    return result


def parse_battery_report(data):
    """Разбор XML-отчёта «powercfg /batteryreport /xml»."""
    if not data:
        return []
    result = []
    for el in ET.fromstring(data).iter():
        if el.tag.rsplit("}", 1)[-1] != "Battery":
            continue
        fields = {c.tag.rsplit("}", 1)[-1]: (c.text or "").strip() for c in el}
        if "DesignCapacity" not in fields and "FullChargeCapacity" not in fields:
            continue
        result.append({
            "id": fields.get("Id"), "manufacturer": fields.get("Manufacturer"),
            "serial": fields.get("SerialNumber"), "chemistry": fields.get("Chemistry"),
            "design": to_int(fields.get("DesignCapacity")), "full": to_int(fields.get("FullChargeCapacity")),
            "cycles": to_int(fields.get("CycleCount")),
        })
    return result


def battery_report():
    """Паспортная и текущая ёмкость батареи из отчёта powercfg.

    WMI-класс BatteryStaticData на многих ноутбуках отвечает «Общий сбой»,
    а powercfg получает те же сведения напрямую у драйвера батареи.
    """
    exe = shutil.which("powercfg") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                                    "System32", "powercfg.exe")
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        proc = subprocess.run([exe, "/batteryreport", "/output", path, "/xml"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60, creationflags=CREATE_NO_WINDOW)
        with open(path, "rb") as fh:
            data = fh.read()
        if not data:
            message = decode_console(proc.stdout + proc.stderr).strip()
            if "0x422" in message:
                message += (" Отключена «Служба политики диагностики» (DPS): без неё powercfg не строит "
                            "отчёт о батарее.")
            raise RuntimeError(f"powercfg не создал отчёт (код {proc.returncode})" + (f": {message}" if message else ""))
        return parse_battery_report(data)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


BATTERY_CAPACITY_RELATIVE = 0x40000000
BATTERY_UNKNOWN_CAPACITY = 0xFFFFFFFF


def battery_ioctl():
    """Сведения о батарее напрямую от драйвера (IOCTL_BATTERY_QUERY_INFORMATION).

    Так их получает сама Windows для значка батареи. Способ не зависит ни от
    WMI-класса BatteryStaticData, ни от службы политики диагностики, без
    которой не работает отчёт powercfg.
    """
    u32, i32, ptr = ctypes.c_uint32, ctypes.c_int32, ctypes.c_void_p
    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", u32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8)]

    class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
        _fields_ = [("cbSize", u32), ("InterfaceClassGuid", GUID), ("Flags", u32), ("Reserved", ctypes.c_size_t)]

    class BATTERY_QUERY_INFORMATION(ctypes.Structure):
        _fields_ = [("BatteryTag", u32), ("InformationLevel", i32), ("AtRate", i32)]

    class BATTERY_INFORMATION(ctypes.Structure):
        _fields_ = [("Capabilities", u32), ("Technology", ctypes.c_ubyte), ("Reserved", ctypes.c_ubyte * 3),
                    ("Chemistry", ctypes.c_ubyte * 4), ("DesignedCapacity", u32), ("FullChargedCapacity", u32),
                    ("DefaultAlert1", u32), ("DefaultAlert2", u32), ("CriticalBias", u32), ("CycleCount", u32)]

    setupapi.SetupDiGetClassDevsW.restype = ptr
    setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), ctypes.c_wchar_p, ptr, u32]
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [ptr, ptr, ctypes.POINTER(GUID), u32,
                                                     ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [ptr, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ptr, u32,
                                                          ctypes.POINTER(u32), ptr]
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ptr]
    kernel32.CreateFileW.restype = ptr
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, u32, u32, ptr, u32, u32, ptr]
    kernel32.DeviceIoControl.argtypes = [ptr, u32, ptr, u32, ptr, u32, ctypes.POINTER(u32), ptr]
    kernel32.CloseHandle.argtypes = [ptr]

    invalid = ctypes.c_void_p(-1).value
    ioctl_query_tag, ioctl_query_info = 0x294040, 0x294044
    # GUID_DEVICE_BATTERY {72631E54-78A4-11D0-BCF7-00AA00B7B32A}
    guid = GUID(0x72631E54, 0x78A4, 0x11D0, (ctypes.c_ubyte * 8)(0xBC, 0xF7, 0x00, 0xAA, 0x00, 0xB7, 0xB3, 0x2A))
    hdev = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), None, None, 0x2 | 0x10)  # PRESENT | DEVICEINTERFACE
    if not hdev or hdev == invalid:
        raise OSError(ctypes.get_last_error(), "не удалось получить список батарей")
    result = []
    try:
        for index in range(8):
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(did)
            if not setupapi.SetupDiEnumDeviceInterfaces(hdev, None, ctypes.byref(guid), index, ctypes.byref(did)):
                break
            need = u32(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), None, 0, ctypes.byref(need), None)
            if need.value < 8:
                continue
            detail = ctypes.create_string_buffer(need.value)
            # cbSize структуры SP_DEVICE_INTERFACE_DETAIL_DATA_W: 8 в 64-битном процессе, 6 в 32-битном
            ctypes.cast(detail, ctypes.POINTER(u32))[0] = 8 if ctypes.sizeof(ptr) == 8 else 6
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), detail, need, None, None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
            handle = None
            for access in (0xC0000000, 0x80000000):  # чтение и запись, затем только чтение
                handle = kernel32.CreateFileW(path, access, 0x3, None, 3, 0x80, None)  # OPEN_EXISTING
                if handle and handle != invalid:
                    break
                handle = None
            if not handle:
                continue
            try:
                returned, wait, tag = u32(0), u32(0), u32(0)
                if not kernel32.DeviceIoControl(handle, ioctl_query_tag, ctypes.byref(wait), 4, ctypes.byref(tag), 4,
                                                ctypes.byref(returned), None) or not tag.value:
                    continue

                def query(level, out):
                    q = BATTERY_QUERY_INFORMATION(tag.value, level, 0)
                    return kernel32.DeviceIoControl(handle, ioctl_query_info, ctypes.byref(q), ctypes.sizeof(q),
                                                    ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(returned), None)

                def text(level):
                    buf = ctypes.create_unicode_buffer(128)
                    return clean(buf.value) if query(level, buf) else None

                info = BATTERY_INFORMATION()
                if not query(0, info):  # уровень BatteryInformation
                    continue

                def capacity(value):
                    return value if value and value != BATTERY_UNKNOWN_CAPACITY else None

                class BATTERY_MANUFACTURE_DATE(ctypes.Structure):
                    _fields_ = [("Day", ctypes.c_ubyte), ("Month", ctypes.c_ubyte), ("Year", ctypes.c_uint16)]

                made = BATTERY_MANUFACTURE_DATE()
                manufactured = None
                if query(5, made) and 1 <= made.Month <= 12 and 1990 <= made.Year <= 2100:  # BatteryManufactureDate
                    manufactured = f"{made.Year:04d}-{made.Month:02d}-{made.Day or 1:02d}"

                result.append({
                    "id": text(4), "manufacturer": text(6), "serial": text(8),  # имя, производитель, серийный номер
                    "chemistry": bytes(info.Chemistry).decode("ascii", "ignore").strip("\x00 "),
                    "design": capacity(info.DesignedCapacity), "full": capacity(info.FullChargedCapacity),
                    "cycles": info.CycleCount or None, "manufactured": manufactured,
                    "relative": bool(info.Capabilities & BATTERY_CAPACITY_RELATIVE),
                })
            finally:
                kernel32.CloseHandle(handle)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return result


def nvme_health_windows(disk_numbers):
    """Журнал SMART/Health NVMe-дисков напрямую у контроллера (нужны права администратора).

    Стандартные счётчики Windows часто не сообщают наработку и объём записанного,
    а в журнале самого диска они есть всегда.
    """
    u32, ptr = ctypes.c_uint32, ctypes.c_void_p
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ptr
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, u32, u32, ptr, u32, u32, ptr]
    kernel32.DeviceIoControl.argtypes = [ptr, u32, ptr, u32, ptr, u32, ctypes.POINTER(u32), ptr]
    kernel32.CloseHandle.argtypes = [ptr]
    invalid = ctypes.c_void_p(-1).value
    result = {}
    for number in disk_numbers:
        handle = kernel32.CreateFileW(f"\\\\.\\PhysicalDrive{number}", 0xC0000000, 0x3, None, 3, 0, None)
        if not handle or handle == invalid:
            continue
        try:
            # STORAGE_PROPERTY_QUERY (8 байт) + STORAGE_PROTOCOL_SPECIFIC_DATA (40 байт) + журнал (512 байт)
            buf = ctypes.create_string_buffer(8 + 40 + 512)
            struct.pack_into("<II", buf, 0, 50, 0)  # StorageDeviceProtocolSpecificProperty, PropertyStandardQuery
            struct.pack_into("<10I", buf, 8, 3, 2, 2, 0, 40, 512, 0, 0, 0, 0)  # NVMe, лог-страница 02h
            returned = u32(0)
            if not kernel32.DeviceIoControl(handle, 0x2D1400, buf, len(buf), buf, len(buf),  # IOCTL_STORAGE_QUERY_PROPERTY
                                            ctypes.byref(returned), None):
                continue
            version, size = struct.unpack_from("<II", buf, 0)
            offset, length = struct.unpack_from("<II", buf, 8 + 16)
            if version != 48 or size != 48 or offset < 40 or length < 512:
                continue
            result[str(number)] = parse_nvme_health(buf.raw[8 + offset:8 + offset + 512])
        finally:
            kernel32.CloseHandle(handle)
    return result


def collect_local(has_battery=False, nvme_disks=()):
    info = {"is_admin": is_admin()}
    if not IS_WINDOWS:
        return info
    steps = {
        "firmware": firmware_type,
        "secure_boot": lambda: reg_value(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                                         "UEFISecureBootEnabled"),
        "display_version": lambda: (reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion")
                                    or reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId")),
        "ubr": lambda: reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR"),
        "gpu_registry": gpu_registry,
        "edid": read_edids,
        "displays": display_modes,
    }
    if nvme_disks and info["is_admin"]:
        steps["nvme_health"] = lambda: nvme_health_windows(nvme_disks)
    if has_battery:
        steps["battery_ioctl"] = battery_ioctl
        # Отчёт powercfg — запасной путь, если драйвер не отдал паспортную ёмкость
        steps["battery_report"] = lambda: (None if any(b.get("design") for b in info.get("battery_ioctl") or [])
                                           else battery_report())
    for key, func in steps.items():
        try:
            value = func()
            if value is not None:
                info[key] = value
        except Exception as exc:  # отдельная неудача не должна ломать весь отчёт
            info.setdefault("errors", {})[key] = str(exc)
    return info


# ---------------------------------------------------------------------------
# Сбор данных в Linux: напрямую из ядра (/sys, /proc) и таблиц прошивки SMBIOS
# ---------------------------------------------------------------------------

LINUX_ROOT = "/"  # откуда читаются /sys, /proc, /etc и /run (другой корень — только в тестах)


def _lp(path):
    return os.path.join(LINUX_ROOT, path.lstrip("/"))


def lread(path, binary=False):
    try:
        with open(_lp(path), "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return data if binary else data.decode("utf-8", "replace").strip()


def lexists(path):
    return os.path.exists(_lp(path))


def llist(path):
    try:
        return sorted(os.listdir(_lp(path)))
    except OSError:
        return []


def lreal(path):
    return os.path.realpath(_lp(path))


def llink(path):
    """Имя, на которое указывает ссылка в /sys (например, драйвер устройства)."""
    try:
        return os.path.basename(os.readlink(_lp(path)))
    except OSError:
        return None


def lhex(path):
    try:
        return int(lread(path) or "", 16)
    except ValueError:
        return None


def run_tool(args, timeout=30):
    """Вывод внешней программы (smartctl, ip, nvidia-smi) или None, если её нет."""
    if not shutil.which(args[0]):
        return None
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.decode("utf-8", "replace")


class SmbiosStruct:
    """Одна структура SMBIOS: байты формата и набор строк."""

    def __init__(self, raw, strings):
        self.raw, self.strings = raw, strings

    def _int(self, off, size):
        return int.from_bytes(self.raw[off:off + size], "little") if off + size <= len(self.raw) else None

    def byte(self, off):
        return self._int(off, 1)

    def word(self, off):
        return self._int(off, 2)

    def dword(self, off):
        return self._int(off, 4)

    def qword(self, off):
        return self._int(off, 8)

    def text(self, off):
        idx = self.byte(off)
        return clean(self.strings[idx - 1]) if idx and idx <= len(self.strings) else None


def parse_smbios(data):
    """Таблицы SMBIOS (те же, что читает dmidecode): [(тип, SmbiosStruct)]."""
    result, i = [], 0
    while i + 4 <= len(data):
        stype, length = data[i], data[i + 1]
        if length < 4:
            break
        end = data.find(b"\x00\x00", i + length)
        if end < 0:
            break
        raw = data[i + length:end]
        strings = [s.decode("latin-1").strip() for s in raw.split(b"\x00")] if raw else []
        result.append((stype, SmbiosStruct(data[i:i + length], strings)))
        if stype == 127:  # конец таблицы
            break
        i = end + 2
    return result


def smbios_date(value):
    m = re.match(r"(\d{1,2})/(\d{1,2})/(\d{2,4})$", value or "")
    if not m:
        return None
    year = int(m.group(3))
    if year < 100:
        year += 1900 if year >= 70 else 2000
    return f"{year:04d}-{int(m.group(1)):02d}-{int(m.group(2)):02d}T00:00:00"


def smbios_uuid(b):
    if len(b) != 16 or b in (b"\x00" * 16, b"\xff" * 16):
        return None
    return (f"{int.from_bytes(b[0:4], 'little'):08X}-{int.from_bytes(b[4:6], 'little'):04X}-"
            f"{int.from_bytes(b[6:8], 'little'):04X}-{b[8:10].hex().upper()}-{b[10:16].hex().upper()}")


# Форм-фактор модуля памяти: коды SMBIOS -> коды WMI, по которым строится отчёт
SMBIOS_TO_CIM_FORM = {3: 7, 9: 8, 11: 21, 12: 11, 13: 12, 14: 13}


def linux_smbios(data):
    out = {"bios": [], "product": [], "baseboard": [], "enclosure": [], "sockets": [], "memarray": [], "memory": []}
    for stype, s in parse_smbios(data):
        if stype == 0:
            out["bios"].append({
                "Manufacturer": s.text(0x04), "SMBIOSBIOSVersion": s.text(0x05),
                "ReleaseDate": smbios_date(s.text(0x08)),
                "EmbeddedControllerMajorVersion": s.byte(0x16), "EmbeddedControllerMinorVersion": s.byte(0x17)})
        elif stype == 1:
            out["product"].append({
                "Vendor": s.text(0x04), "Name": s.text(0x05), "Version": s.text(0x06),
                "IdentifyingNumber": s.text(0x07), "UUID": smbios_uuid(s.raw[0x08:0x18]),
                "SKU": s.text(0x19), "Family": s.text(0x1A)})
        elif stype == 2:
            out["baseboard"].append({"Manufacturer": s.text(0x04), "Product": s.text(0x05),
                                     "Version": s.text(0x06), "SerialNumber": s.text(0x07)})
        elif stype == 3:
            kind = s.byte(0x05)
            out["enclosure"].append({"Manufacturer": s.text(0x04), "ChassisTypes": [kind & 0x7F] if kind else [],
                                     "SerialNumber": s.text(0x07), "SMBIOSAssetTag": s.text(0x08)})
        elif stype == 4:
            status = s.byte(0x18)
            if status is not None and not status & 0x40:  # пустой сокет
                continue
            cores, threads = s.byte(0x23), s.byte(0x25)
            if cores == 0xFF:
                cores = s.word(0x2A)
            if threads == 0xFF:
                threads = s.word(0x2E)
            out["sockets"].append({"SocketDesignation": s.text(0x04), "Manufacturer": s.text(0x07),
                                   "Name": s.text(0x10), "MaxSpeed": s.word(0x14), "CurrentSpeed": s.word(0x16),
                                   "Cores": cores, "Threads": threads})
        elif stype == 16:
            max_kb = s.dword(0x07)
            if max_kb == 0x80000000:
                ext = s.qword(0x0F)
                max_kb = ext // 1024 if ext else None
            out["memarray"].append({"Use": s.byte(0x05), "MaxCapacity": max_kb, "MemoryDevices": s.word(0x0D)})
        elif stype == 17:
            size = s.word(0x0C)
            if not size:  # пустой слот
                continue
            if size == 0xFFFF:
                capacity = None
            elif size == 0x7FFF:
                capacity = ((s.dword(0x1C) or 0) & 0x7FFFFFFF) * 1024 * 1024
            else:
                capacity = (size & 0x7FFF) * (1024 if size & 0x8000 else 1024 * 1024)
            speed, configured = s.word(0x15), s.word(0x20)
            if speed == 0xFFFF:
                speed = s.dword(0x54)
            if configured == 0xFFFF:
                configured = s.dword(0x58)
            data_width, total_width = s.word(0x0A), s.word(0x08)
            out["memory"].append({
                "DeviceLocator": s.text(0x10), "BankLabel": s.text(0x11), "Capacity": capacity,
                "Speed": speed or None, "ConfiguredClockSpeed": configured or None,
                "Manufacturer": s.text(0x17), "SerialNumber": s.text(0x18), "PartNumber": s.text(0x1A),
                "SMBIOSMemoryType": s.byte(0x12), "FormFactor": SMBIOS_TO_CIM_FORM.get(s.byte(0x0E)),
                "DataWidth": None if data_width in (None, 0xFFFF) else data_width,
                "TotalWidth": None if total_width in (None, 0xFFFF) else total_width,
                "ConfiguredVoltage": s.word(0x26) or None})
    return out


def bcd(value):
    hi, lo = value >> 4, value & 0x0F
    return hi * 10 + lo if hi < 10 and lo < 10 else None


# Где в SPD лежат производитель модуля, дата, серийный номер и партномер: (тип, смещения…, длина партномера)
SPD_LAYOUTS = {0x0B: ("DDR3", 117, 120, 122, 128, 18), 0x0C: ("DDR4", 320, 323, 325, 329, 20),
               0x0E: ("DDR4", 320, 323, 325, 329, 20), 0x12: ("DDR5", 512, 515, 517, 521, 30)}


def parse_spd(data):
    """Данные из микросхемы SPD модуля памяти — то же, что показывают CPU-Z и decode-dimms."""
    layout = SPD_LAYOUTS.get(data[2]) if data and len(data) > 2 else None
    if not layout:
        return None
    kind, mfr, date, serial, part, part_len = layout
    if len(data) < part + part_len:
        return None
    year, week = bcd(data[date]), bcd(data[date + 1])
    serial_hex = data[serial:serial + 4].hex().upper()
    return {
        "type": kind, "vendor": f"{data[mfr]:02X}{data[mfr + 1]:02X}",
        "year": 2000 + year if year else None, "week": week if week and 1 <= week <= 53 else None,
        "serial": serial_hex if serial_hex not in ("00000000", "FFFFFFFF") else None,
        "part": clean(data[part:part + part_len].decode("ascii", "replace")),
    }


def linux_spd():
    """Микросхемы SPD модулей памяти (адреса 0x50–0x57 на шине SMBus)."""
    result = []
    for driver in ("ee1004", "spd5118", "at24", "eeprom"):
        for dev in llist(f"/sys/bus/i2c/drivers/{driver}"):
            if not re.fullmatch(r"\d+-005[0-7]", dev):
                continue
            info = parse_spd(lread(f"/sys/bus/i2c/drivers/{driver}/{dev}/eeprom", binary=True))
            if info:
                result.append(dict(info, address=dev))
    return result


def smbios_version():
    ep = lread("/sys/firmware/dmi/tables/smbios_entry_point", binary=True) or b""
    if ep.startswith(b"_SM3_") and len(ep) > 8:
        return ep[7], ep[8]
    if ep.startswith(b"_SM_") and len(ep) > 7:
        return ep[6], ep[7]
    return None, None


def dmi_id(name):
    return clean(lread(f"/sys/class/dmi/id/{name}"))


def parse_ids(text):
    """База названий устройств pci.ids / usb.ids."""
    vendors, devices, subsystems = {}, {}, {}
    vendor = device = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith("\t"):
            m = re.match(r"([0-9a-fA-F]{4})\s+(.+)", line)
            if not m:  # начались классы устройств — производители закончились
                break
            vendor, device = m.group(1).upper(), None
            vendors[vendor] = m.group(2).strip()
        elif line.startswith("\t\t"):
            m = re.match(r"\t\t([0-9a-fA-F]{4})\s+([0-9a-fA-F]{4})\s+(.+)", line)
            if m and vendor and device:
                subsystems[(vendor, device, m.group(1).upper(), m.group(2).upper())] = m.group(3).strip()
        else:
            m = re.match(r"\t([0-9a-fA-F]{4})\s+(.+)", line)
            if m and vendor:
                device = m.group(1).upper()
                devices[(vendor, device)] = m.group(2).strip()
    return {"vendors": vendors, "devices": devices, "subsystems": subsystems}


def load_ids(kind):
    folders = ("/usr/share/hwdata", "/usr/share/misc", "/usr/share", f"/var/lib/{kind}utils")
    for folder in folders:
        for suffix in ("", ".gz"):
            data = lread(f"{folder}/{kind}.ids{suffix}", binary=True)
            if not data:
                continue
            if suffix:
                try:
                    data = gzip.decompress(data)
                except OSError:
                    continue
            return parse_ids(data.decode("utf-8", "replace"))
    return None


def pretty_pci_name(name):
    """«GA106M [GeForce RTX 3060 Mobile / Max-Q]» -> «GeForce RTX 3060 Mobile / Max-Q (GA106M)»."""
    m = re.fullmatch(r"(.+?)\s*\[(.+)\]", name or "")
    if m and " " in m.group(2):  # в скобках торговое название, а не короткий код вроде [E18]
        return f"{m.group(2)} ({m.group(1)})"
    return name


def pci_pnp_class(cls):
    base, sub = cls >> 16, (cls >> 8) & 0xFF
    if base == 0x01:
        return "HDC" if sub == 0x06 else "SCSIAdapter"
    if (base, sub) == (0x0C, 0x03):
        return "USB"
    if (base, sub) == (0x0D, 0x11):
        return "Bluetooth"
    return {0x02: "Net", 0x03: "Display", 0x04: "MEDIA", 0x09: "HIDClass", 0x0D: "Net",
            0x10: "SecurityDevices"}.get(base, "System")


def linux_pci(ids):
    devices = []
    for addr in llist("/sys/bus/pci/devices"):
        base = f"/sys/bus/pci/devices/{addr}"
        ven, dev = lhex(base + "/vendor"), lhex(base + "/device")
        if ven is None or dev is None:
            continue
        sub_ven, sub_dev, cls = lhex(base + "/subsystem_vendor"), lhex(base + "/subsystem_device"), lhex(base + "/class") or 0
        v, d = f"{ven:04X}", f"{dev:04X}"
        name = vendor = None
        if ids:
            vendor = ids["vendors"].get(v)
            name = ids["devices"].get((v, d))
            if sub_ven is not None and cls >> 16 in (0x02, 0x0D):  # у сетевых карт понятнее имя модели
                name = ids["subsystems"].get((v, d, f"{sub_ven:04X}", f"{sub_dev or 0:04X}")) or name
        driver = llink(base + "/driver")
        module = llink(base + "/driver/module")
        devices.append({
            "addr": addr, "class": cls, "name": pretty_pci_name(name) or f"PCI-устройство {v}:{d}",
            "vendor": vendor or PCI_VENDORS.get(v), "short_vendor": PCI_VENDORS.get(v),
            "driver": driver, "driver_version": lread(f"/sys/module/{module}/version") if module else None,
            "pnp": f"PCI\\VEN_{v}&DEV_{d}&SUBSYS_{sub_dev or 0:04X}{sub_ven or 0:04X}\\{addr}",
        })
    return devices


USB_CLASS_PNP = {0x01: "MEDIA", 0x02: "Ports", 0x03: "HIDClass", 0x06: "Image", 0x07: "Printer", 0x08: "USB",
                 0x09: "USB", 0x0A: "Ports", 0x0B: "SmartCardReader", 0x0E: "Camera"}
FINGERPRINT_VENDORS = {"06CB", "27C6", "138A", "10A5", "1C7A", "2808", "298D"}


def linux_usb(ids):
    devices = []
    for name in llist("/sys/bus/usb/devices"):
        if ":" in name:  # интерфейсы, а не устройства
            continue
        base = f"/sys/bus/usb/devices/{name}"
        vid, pid = (lread(base + "/idVendor") or "").upper(), (lread(base + "/idProduct") or "").upper()
        if not vid:
            continue
        ifaces = []
        for iface in llist(base):
            if iface.startswith(name + ":"):
                ib = f"{base}/{iface}"
                ifaces.append((lhex(ib + "/bInterfaceClass"), lhex(ib + "/bInterfaceSubClass"), llink(ib + "/driver")))
        dev_class = lhex(base + "/bDeviceClass") or 0
        classes = [c for c, _, _ in ifaces if c is not None] or [dev_class]
        root = name.startswith("usb")
        speed = to_int((lread(base + "/speed") or "").split(".")[0])
        if root or dev_class == 0x09:
            pnp_class = "USB"
        elif 0x0E in classes:
            pnp_class = "Camera"
        elif any(c == 0xE0 and sc == 0x01 for c, sc, _ in ifaces):
            pnp_class = "Bluetooth"
        else:
            pnp_class = next((USB_CLASS_PNP[c] for c in classes if c in USB_CLASS_PNP), None)
            if not pnp_class:
                pnp_class = "Biometric" if vid in FINGERPRINT_VENDORS else "USBDevice"
        product, maker = clean(lread(base + "/product")), clean(lread(base + "/manufacturer"))
        if ids:
            product = product or ids["devices"].get((vid, pid))
            maker = maker or ids["vendors"].get(vid)
        if root:
            product = f"Корневой USB-концентратор (USB {'3.x' if speed and speed >= 5000 else '2.0' if speed == 480 else '1.1'})"
        drivers = [drv for _, _, drv in ifaces if drv]
        devices.append({
            "busname": name, "class": pnp_class, "name": product or f"USB-устройство {vid}:{pid}", "vendor": maker,
            "driver": drivers[0] if drivers else None, "ifaces": ifaces,
            "pnp": f"USB\\ROOT_HUB\\{name}" if root else f"USB\\VID_{vid}&PID_{pid}\\{name}",
        })
    return devices


def linux_cpu_caches():
    totals, seen = {}, set()
    for cpu in llist("/sys/devices/system/cpu"):
        if not re.fullmatch(r"cpu\d+", cpu):
            continue
        for index in llist(f"/sys/devices/system/cpu/{cpu}/cache"):
            base = f"/sys/devices/system/cpu/{cpu}/cache/{index}"
            level, kind = to_int(lread(base + "/level")), lread(base + "/type")
            m = re.match(r"(\d+)\s*([KMG]?)", lread(base + "/size") or "")
            if not level or kind == "Instruction" or not m:
                continue
            key = (level, kind, lread(base + "/shared_cpu_list"))
            if key in seen:
                continue
            seen.add(key)
            kb = int(m.group(1)) * {"": 1 / 1024, "K": 1, "M": 1024, "G": 1024 * 1024}[m.group(2)]
            totals[level] = totals.get(level, 0) + int(kb)
    return totals


def linux_cpu(sockets_smbios):
    procs = []
    for block in (lread("/proc/cpuinfo") or "").split("\n\n"):
        info = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
        if info.get("processor") is not None:
            procs.append(info)
    flags = set()
    if procs:
        flags = set(procs[0].get("flags", "").split()) | set(procs[0].get("vmx flags", "").split())
    machine = platform.machine().lower()
    x86 = machine in ("x86_64", "amd64", "i386", "i686")
    sockets = OrderedDict()
    for p in procs:
        sockets.setdefault(p.get("physical id", "0"), []).append(p)
    caches = linux_cpu_caches()
    base_khz = to_int(lread("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency"))
    max_khz = to_int(lread("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"))
    rows = []
    for n, items in enumerate(sockets.values() or [[]]):
        first = items[0] if items else {}
        sm = sockets_smbios[n] if n < len(sockets_smbios) else {}
        name = clean(first.get("model name")) or sm.get("Name") or clean(first.get("Hardware"))
        core_ids = {p.get("core id") for p in items if p.get("core id") is not None}
        base_mhz = base_khz // 1000 if base_khz else sm.get("CurrentSpeed")
        if not base_mhz and name:
            m = re.search(r"@\s*([\d.]+)\s*GHz", name)
            base_mhz = round(float(m.group(1)) * 1000) if m else None
        caption = None
        if first.get("cpu family"):
            caption = f"Family {first.get('cpu family')} Model {first.get('model')} Stepping {first.get('stepping')}"
        rows.append({
            "Name": name, "Manufacturer": first.get("vendor_id") or sm.get("Manufacturer"), "Caption": caption,
            "NumberOfCores": len(core_ids) or sm.get("Cores") or len(items) or None,
            "NumberOfLogicalProcessors": len(items) or sm.get("Threads"),
            "MaxClockSpeed": base_mhz, "MaxTurboMHz": max_khz // 1000 if max_khz else None,
            "L2CacheSize": caches.get(2, 0) // max(1, len(sockets)) or None,
            "L3CacheSize": caches.get(3, 0) // max(1, len(sockets)) or None,
            "SocketDesignation": sm.get("SocketDesignation"),
            "Architecture": {"x86_64": 9, "amd64": 9, "i386": 0, "i686": 0, "aarch64": 12, "armv7l": 5}.get(machine),
            "AddressWidth": 64 if machine in ("x86_64", "amd64", "aarch64") else 32,
            "VirtualizationFirmwareEnabled": bool(flags & {"vmx", "svm"}) if x86 else None,
            "SecondLevelAddressTranslationExtensions": bool(flags & {"ept", "npt"}) if x86 else None,
        })
    return rows, "hypervisor" in flags


def udev_props(devnum):
    """Свойства устройства из базы udev (тип раздела, файловая система, серийный номер)."""
    props = {}
    for line in (lread(f"/run/udev/data/b{devnum}") or "").splitlines() if devnum else []:
        if line.startswith("E:") and "=" in line:
            key, value = line[2:].split("=", 1)
            props[key] = value
    return props


def parse_smartctl(js):
    r = {}
    passed = (js.get("smart_status") or {}).get("passed")
    r["Health"] = None if passed is None else (0 if passed else 2)
    r["Temperature"] = (js.get("temperature") or {}).get("current")
    r["PowerOnHours"] = (js.get("power_on_time") or {}).get("hours")
    r["StartStopCycleCount"] = js.get("power_cycle_count")
    nv = js.get("nvme_smart_health_information_log") or {}
    if nv:
        r["Wear"] = nv.get("percentage_used")
        r["DataWrittenBytes"] = (nv.get("data_units_written") or 0) * 512000 or None
        r["ReadErrorsUncorrected"] = nv.get("media_errors")
        r["CriticalWarning"] = nv.get("critical_warning")
        r["UnsafeShutdowns"] = nv.get("unsafe_shutdowns")
    attrs = {a.get("id"): a for a in (js.get("ata_smart_attributes") or {}).get("table", [])}
    if attrs:
        def raw(aid):
            return ((attrs.get(aid) or {}).get("raw") or {}).get("value")

        r["ReallocatedSectors"], r["PendingSectors"] = raw(5), raw(197)
        r["ReadErrorsUncorrected"] = raw(198)
        if raw(241):
            r["DataWrittenBytes"] = raw(241) * (js.get("logical_block_size") or 512)
        for aid in (231, 233, 177, 169):  # «остаток ресурса» у разных производителей SSD
            value = (attrs.get(aid) or {}).get("value")
            if value is not None and 0 <= value <= 100:
                r["Wear"] = 100 - value
                break
    return {k: v for k, v in r.items() if v is not None}


def parse_nvme_health(log):
    """Журнал NVMe SMART/Health (512 байт, лог-страница 02h)."""
    def u128(off):
        return int.from_bytes(log[off:off + 16], "little")

    kelvin = int.from_bytes(log[1:3], "little")
    return {
        "Health": 1 if log[0] else 0, "CriticalWarning": log[0], "Temperature": kelvin - 273 if kelvin else None,
        "Wear": log[5], "DataWrittenBytes": u128(48) * 512000, "StartStopCycleCount": u128(112),
        "PowerOnHours": u128(128), "UnsafeShutdowns": u128(144), "ReadErrorsUncorrected": u128(160),
    }


def nvme_smart_log(controller):
    """Журнал SMART/Health прямо у NVMe-контроллера (команда Get Log Page, как у nvme-cli)."""
    import fcntl
    buf = ctypes.create_string_buffer(512)
    cmd = bytearray(struct.pack("<BBHIIIQQIIIIIIIIII",
                                0x02, 0, 0, 0xFFFFFFFF,  # opcode Get Log Page, все пространства имён
                                0, 0, 0, ctypes.addressof(buf), 0, 512,
                                (127 << 16) | 0x02,  # 128 двойных слов, журнал 02h SMART/Health
                                0, 0, 0, 0, 0, 0, 0))
    fd = os.open(controller, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, 0xC0484E41, cmd)  # NVME_IOCTL_ADMIN_CMD
    finally:
        os.close(fd)
    return parse_nvme_health(buf.raw)


def linux_smart(name, errors):
    out = run_tool(["smartctl", "-j", "-a", f"/dev/{name}"])
    if out:
        try:
            parsed = parse_smartctl(json.loads(out))
            if parsed:
                return parsed
        except ValueError:
            pass
    m = re.match(r"(nvme\d+)", name)
    if m:
        try:
            return nvme_smart_log(_lp(f"/dev/{m.group(1)}"))
        except (OSError, ValueError) as exc:
            errors.setdefault("smart", f"{name}: {exc}")
    elif not shutil.which("smartctl"):
        errors.setdefault("smart", "для SMART-показателей SATA- и USB-дисков установите smartmontools "
                                   "(sudo apt install smartmontools)")
    return {}


def unescape_mount(path):
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), path)


def linux_storage(is_root, errors):
    mounts = {}
    for line in (lread("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("/dev/"):
            mounts.setdefault(parts[0], []).append((unescape_mount(parts[1]), parts[2]))
    disks, partitions, volumes, health, cdroms = [], [], [], [], []

    def volume(mount, fs, label, disk_id, removable):
        try:
            st = os.statvfs(mount)
            size, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        except OSError:
            size = free = None
        volumes.append({"DeviceID": mount, "VolumeName": label, "FileSystem": fs, "Size": size, "FreeSpace": free,
                        "DriveType": 2 if removable else 3, "DiskNumber": disk_id})

    for name in llist("/sys/block"):
        base = f"/sys/block/{name}"
        if name.startswith("sr"):
            vendor, model = clean(lread(base + "/device/vendor")), clean(lread(base + "/device/model"))
            cdroms.append({"Name": " ".join(x for x in (vendor, model) if x) or name, "Drive": f"/dev/{name}",
                           "Manufacturer": vendor})
            continue
        if name.startswith(("loop", "ram", "zram", "dm-", "md", "fd", "nbd", "zd")):
            continue
        size = (to_int(lread(base + "/size")) or 0) * 512
        if not size:
            continue
        devpath = lreal(base + "/device")
        removable = lread(base + "/removable") == "1"
        udev = udev_props(lread(base + "/dev"))
        if name.startswith("nvme"):
            bus, model = 17, clean(lread(base + "/device/model"))
            serial, firmware = clean(lread(base + "/device/serial")), clean(lread(base + "/device/firmware_rev"))
        elif name.startswith("mmcblk"):
            bus, model = 13, clean(lread(base + "/device/name"))
            serial, firmware = clean(lread(base + "/device/serial")), clean(lread(base + "/device/fwrev"))
        else:
            bus = (7 if "/usb" in devpath else 11 if "/ata" in devpath else 14 if "/virtio" in devpath or name.startswith("vd")
                   else 10 if "/sas" in devpath else 1)
            vendor, model = clean(lread(base + "/device/vendor")), clean(lread(base + "/device/model"))
            if vendor and model and vendor.upper() != "ATA" and not model.upper().startswith(vendor.upper()):
                model = f"{vendor} {model}"
            serial, firmware = clean(udev.get("ID_SERIAL_SHORT")), clean(lread(base + "/device/rev"))
        media = None if bus in (7, 14) else (3 if lread(base + "/queue/rotational") == "1" else 4)
        disk_id = str(len(disks))
        smart = linux_smart(name, errors) if is_root and bus != 14 else {}  # у виртуальных дисков SMART нет
        disks.append({"DeviceId": disk_id, "FriendlyName": model or name, "SerialNumber": serial, "MediaType": media,
                      "BusType": bus, "Size": size, "HealthStatus": smart.pop("Health", None),
                      "FirmwareVersion": firmware})
        if smart:
            health.append(dict(smart, DeviceId=disk_id))
        for part in llist(base):
            pbase = f"{base}/{part}"
            if not part.startswith(name) or not lexists(pbase + "/partition"):
                continue
            pu = udev_props(lread(pbase + "/dev"))
            ptype = (pu.get("ID_PART_ENTRY_TYPE") or "").lower()
            mps = mounts.get(f"/dev/{part}", [])
            partitions.append({
                "DiskNumber": disk_id, "PartitionNumber": to_int(lread(pbase + "/partition")),
                "MountPoint": mps[0][0] if mps else None, "Size": (to_int(lread(pbase + "/size")) or 0) * 512,
                "GptType": "{" + ptype + "}" if re.fullmatch(r"[0-9a-f-]{36}", ptype) else None,
                "MbrType": int(ptype, 16) if re.fullmatch(r"0x[0-9a-f]+", ptype) else None,
                "IsSystem": ptype == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "IsBoot": any(mp == "/" for mp, _ in mps),
                "FileSystem": pu.get("ID_FS_TYPE"), "Label": pu.get("ID_FS_LABEL"),
            })
            for mount, fs in mps:
                volume(mount, fs, pu.get("ID_FS_LABEL"), disk_id, removable)
        for mount, fs in mounts.get(f"/dev/{name}", []):  # файловая система на весь диск (бывает у флешек)
            volume(mount, fs, udev.get("ID_FS_LABEL"), disk_id, removable)
    return disks, partitions, volumes, health, cdroms


def linux_batteries():
    rows, details = [], []
    for supply in llist("/sys/class/power_supply"):
        base = f"/sys/class/power_supply/{supply}"
        if lread(base + "/type") != "Battery" or lread(base + "/scope") == "Device":  # батареи мышек и т. п.
            continue

        def num(field):
            return to_int(lread(f"{base}/{field}"))

        design, full, unit = num("energy_full_design"), num("energy_full"), None  # мкВт·ч
        if design or full:
            design, full = (design or 0) / 1000, (full or 0) / 1000
        else:  # некоторые батареи сообщают ёмкость в мкА·ч
            design, full, volts = num("charge_full_design") or 0, num("charge_full") or 0, num("voltage_min_design")
            if volts:
                design, full = design * volts / 1e9, full * volts / 1e9
            else:
                design, full, unit = design / 1000, full / 1000, "мА·ч"
        rows.append({
            "Name": clean(lread(base + "/model_name")) or supply, "DeviceID": supply,
            "EstimatedChargeRemaining": num("capacity"),
            "BatteryStatus": {"Charging": 6, "Discharging": 1, "Full": 3, "Not charging": 2}.get(lread(base + "/status") or ""),
            "Chemistry": {"Li-ion": 6, "Li-poly": 8, "NiMH": 5, "NiCd": 4}.get(lread(base + "/technology") or ""),
        })
        details.append({
            "id": clean(lread(base + "/model_name")), "manufacturer": clean(lread(base + "/manufacturer")),
            "serial": clean(lread(base + "/serial_number")), "design": round(design) or None,
            "full": round(full) or None, "cycles": num("cycle_count") or None, "unit": unit,
            "manufactured": (f"{num('manufacture_year'):04d}-{num('manufacture_month') or 1:02d}-{num('manufacture_day') or 1:02d}"
                             if (num("manufacture_year") or 0) > 1990 else None),
        })
    return rows, details


CONNECTOR_TECH = {"VGA": 0, "DVI": 4, "HDMI": 5, "LVDS": 6, "DP": 10, "eDP": 11, "DSI": 11}


def linux_displays(pci_by_addr):
    edids, displays, ids, conns = {}, [], [], []
    for conn in llist("/sys/class/drm"):
        m = re.fullmatch(r"card(\d+)-(.+)", conn)
        if not m or lread(f"/sys/class/drm/{conn}/status") != "connected":
            continue
        key = conn.upper()
        edid = lread(f"/sys/class/drm/{conn}/edid", binary=True)
        if edid and len(edid) >= 128:
            edids[key] = edid.hex()
        card = os.path.basename(lreal(f"/sys/class/drm/card{m.group(1)}/device"))
        kind = re.match(r"[A-Za-z]+", m.group(2))
        displays.append({"instance": key, "adapter": (pci_by_addr.get(card) or {}).get("name")})
        ids.append({"InstanceName": key, "Active": True})
        conns.append({"InstanceName": key, "VideoOutputTechnology": CONNECTOR_TECH.get(kind.group(0) if kind else "")})
    return edids, displays, ids, conns


def linux_input():
    keyboards, mice = [], []
    buses = {"0011": "PS/2 (встроенная)", "0003": "USB", "0018": "I2C (встроенная)", "0005": "Bluetooth"}
    for block in (lread("/proc/bus/input/devices") or "").split("\n\n"):
        info = {"handlers": [], "ev": 0}
        for line in block.splitlines():
            if line.startswith("I:"):
                info.update(re.findall(r"(\w+)=(\w+)", line))
            elif line.startswith("N:"):
                info["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("H:"):
                info["handlers"] = line.split("=", 1)[1].split()
            elif line.startswith("B: EV="):
                info["ev"] = int(line.split("=", 1)[1], 16)
        if not info.get("name"):
            continue
        vid, pid = info.get("Vendor", "0000").upper(), info.get("Product", "0000").upper()
        bus = info.get("Bus", "")
        row = {"Name": info["name"], "Description": buses.get(bus),  # у встроенных PS/2-устройств коды условные
               "PNPDeviceID": f"HID\\VID_{vid}&PID_{pid}" if vid != "0000" and bus in ("0003", "0005", "0018") else None}
        if "kbd" in info["handlers"] and info["ev"] & 0x100000:  # есть автоповтор клавиш — это клавиатура
            keyboards.append(row)
        elif any(h.startswith("mouse") for h in info["handlers"]):
            mice.append(row)
    return keyboards, mice


def linux_network(pci_by_addr, usb_by_name):
    addresses = {}
    out = run_tool(["ip", "-j", "addr"])
    if out:
        try:
            for item in json.loads(out):
                addresses[item.get("ifname")] = [a.get("local") for a in item.get("addr_info", []) if a.get("local")]
        except ValueError:
            pass
    gateways = {}
    for line in (lread("/proc/net/route") or "").splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000" and f[2] != "00000000":
            gateways[f[0]] = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    dns = re.findall(r"^nameserver\s+(\S+)", lread("/etc/resolv.conf") or "", re.M)
    adapters, configs = [], []
    for index, ifname in enumerate(llist("/sys/class/net")):
        base = f"/sys/class/net/{ifname}"
        if not lexists(base + "/device"):  # виртуальные интерфейсы (lo, docker, VPN)
            continue
        dev = os.path.basename(lreal(base + "/device"))
        src = pci_by_addr.get(dev) or usb_by_name.get(dev.split(":")[0]) or {}
        wireless = lexists(base + "/wireless") or lexists(base + "/phy80211")
        state = lread(base + "/operstate")
        up = state == "up" or (state == "unknown" and lread(base + "/carrier") == "1")
        speed = to_int(lread(base + "/speed"))
        adapters.append({
            "Index": index, "Name": src.get("name") or ifname, "Manufacturer": src.get("vendor"),
            "MACAddress": (lread(base + "/address") or "").upper() or None,
            "Speed": speed * 1_000_000 if speed and speed > 0 else None, "NetConnectionID": ifname,
            "NetConnectionStatus": 2 if up else 7, "AdapterType": "Wi-Fi" if wireless else "Ethernet 802.3",
            "PNPDeviceID": src.get("pnp"),
        })
        if addresses.get(ifname):
            configs.append({"Index": index, "IPAddress": addresses[ifname], "DefaultIPGateway": gateways.get(ifname),
                            "DNSServerSearchOrder": dns})
    return adapters, configs


def linux_sound(pci, usb):
    codecs = {}
    for card in llist("/proc/asound"):
        if not re.fullmatch(r"card\d+", card):
            continue
        dev = os.path.basename(lreal(f"/sys/class/sound/{card}/device"))
        for item in llist(f"/proc/asound/{card}"):
            if item.startswith("codec#"):
                m = re.match(r"Codec:\s*(.+)", lread(f"/proc/asound/{card}/{item}") or "")
                if m:
                    codecs.setdefault(dev.split(":")[0], []).append(m.group(1).strip())
    rows = []
    for d in pci:
        if d["class"] >> 8 in (0x0401, 0x0403):
            rows.append({"Name": d["name"], "Manufacturer": d["vendor"], "PNPDeviceID": d["pnp"],
                         "Status": "OK" if d["driver"] else "нет драйвера", "Codecs": codecs.get(d["addr"])})
    for d in usb:
        if d["class"] == "MEDIA":
            rows.append({"Name": d["name"], "Manufacturer": d["vendor"], "PNPDeviceID": d["pnp"],
                         "Status": "OK" if d["driver"] else "нет драйвера", "Codecs": codecs.get(d["busname"])})
    return rows


def linux_gpus(pci):
    nvidia = {}
    out = run_tool(["nvidia-smi", "--query-gpu=pci.bus_id,name,memory.total,driver_version,vbios_version,serial",
                    "--format=csv,noheader,nounits"])
    for line in (out or "").splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) == 6:
            nvidia[f[0].lower()[-12:]] = f
    rows = []
    for d in pci:
        if d["class"] >> 16 != 0x03:
            continue
        nv = nvidia.get(d["addr"].lower()[-12:])
        name = nv[1] if nv else d["name"]
        if not nv and d["short_vendor"] and not name.upper().startswith(d["short_vendor"].upper()):
            name = f"{d['short_vendor']} {name}"
        vram = to_int(lread(f"/sys/bus/pci/devices/{d['addr']}/mem_info_vram_total"))  # AMD
        if nv and to_int(nv[2]):
            vram = to_int(nv[2]) * 1024 * 1024
        driver = " ".join(x for x in (d["driver"], nv[3] if nv else d["driver_version"]) if x)
        vbios = nv[4] if nv else lread(f"/sys/bus/pci/devices/{d['addr']}/vbios_version")  # NVIDIA / AMD
        serial = nv[5] if nv and re.search(r"[1-9A-Za-z]", nv[5] or "") and "N/A" not in nv[5] else None
        rows.append({"Name": name, "AdapterCompatibility": d["vendor"], "VRAM": vram, "DriverVersion": driver or None,
                     "PNPDeviceID": d["pnp"], "Status": "OK" if d["driver"] else "нет драйвера",
                     "VideoBios": clean(vbios), "SerialNumber": clean(serial)})
    return rows


LAPTOP_CHASSIS = {8, 9, 10, 11, 14, 30, 31, 32}
DESKTOP_CHASSIS = {3, 4, 5, 6, 7, 13, 15, 16, 35, 36}


def collect_linux():
    started = time.time()
    is_root = os.geteuid() == 0
    data, errors = {}, {}
    local = {"is_admin": is_root}

    def guard(key, func, default=None):
        try:
            return func()
        except Exception as exc:  # отдельная неудача не должна ломать весь отчёт
            errors[key] = str(exc)
            return default

    # Таблицы прошивки: модули памяти, серийные номера, сокет процессора (нужны права root)
    raw_smbios = lread("/sys/firmware/dmi/tables/DMI", binary=True)
    sm = guard("smbios", lambda: linux_smbios(raw_smbios), {}) if raw_smbios else {}
    if not raw_smbios and is_root:
        errors["smbios"] = "таблицы SMBIOS недоступны"

    def first(key):
        return (sm.get(key) or [{}])[0]

    product, board, enclosure, bios = first("product"), first("baseboard"), first("enclosure"), first("bios")
    chassis = [c for c in enclosure.get("ChassisTypes", [])] or [to_int(dmi_id("chassis_type"))]
    chassis = [c for c in chassis if c]
    mem = dict(re.findall(r"^(\w+):\s+(\d+)", lread("/proc/meminfo") or "", re.M))
    cpu_rows, hypervisor = guard("cpu", lambda: linux_cpu(sm.get("sockets", [])), ([], False))

    data["system"] = [{
        "Name": socket.gethostname(), "Manufacturer": product.get("Vendor") or dmi_id("sys_vendor"),
        "Model": product.get("Name") or dmi_id("product_name"),
        "SystemFamily": product.get("Family") or dmi_id("product_family"),
        "SystemSKUNumber": product.get("SKU") or dmi_id("product_sku"), "SystemType": platform.machine(),
        "PCSystemType": 2 if set(chassis) & LAPTOP_CHASSIS else 1 if set(chassis) & DESKTOP_CHASSIS else None,
        "TotalPhysicalMemory": to_int(mem.get("MemTotal", 0)) * 1024 or None, "HypervisorPresent": hypervisor,
        "UserName": os.environ.get("SUDO_USER") or guard("user", getpass.getuser),
        "NumberOfProcessors": len(cpu_rows) or None,
    }]
    data["product"] = [{
        "Vendor": product.get("Vendor"), "Name": product.get("Name"),
        "Version": product.get("Version") or dmi_id("product_version"),
        "IdentifyingNumber": product.get("IdentifyingNumber") or dmi_id("product_serial"),
        "UUID": product.get("UUID") or dmi_id("product_uuid"),
    }]
    data["enclosure"] = [{"ChassisTypes": chassis, "SerialNumber": enclosure.get("SerialNumber") or dmi_id("chassis_serial"),
                          "SMBIOSAssetTag": enclosure.get("SMBIOSAssetTag") or dmi_id("chassis_asset_tag")}]
    major, minor = smbios_version()
    data["bios"] = [{
        "Manufacturer": bios.get("Manufacturer") or dmi_id("bios_vendor"),
        "SMBIOSBIOSVersion": bios.get("SMBIOSBIOSVersion") or dmi_id("bios_version"),
        "ReleaseDate": bios.get("ReleaseDate") or smbios_date(dmi_id("bios_date")),
        "SMBIOSMajorVersion": major, "SMBIOSMinorVersion": minor,
        "EmbeddedControllerMajorVersion": bios.get("EmbeddedControllerMajorVersion"),
        "EmbeddedControllerMinorVersion": bios.get("EmbeddedControllerMinorVersion"),
    }]
    data["baseboard"] = [{
        "Manufacturer": board.get("Manufacturer") or dmi_id("board_vendor"),
        "Product": board.get("Product") or dmi_id("board_name"),
        "Version": board.get("Version") or dmi_id("board_version"),
        "SerialNumber": board.get("SerialNumber") or dmi_id("board_serial"),
    }]
    data["cpu"] = cpu_rows
    data["memory"], data["memarray"] = sm.get("memory", []), sm.get("memarray", [])
    spd = guard("spd", linux_spd, [])
    by_serial = {m["serial"]: m for m in spd if m.get("serial")}
    for i, module in enumerate(data["memory"]):  # SPD сопоставляется с модулем по серийному номеру
        info = by_serial.get((clean(module.get("SerialNumber")) or "").upper())
        if not info and not by_serial and len(spd) == len(data["memory"]):
            info = spd[i]
        if info:
            module.update(ManufactureYear=info["year"], ManufactureWeek=info["week"])
    if spd and not data["memory"]:  # без прав root модули видны только через SPD
        data["memory"] = [{"Manufacturer": m["vendor"], "PartNumber": m["part"], "SerialNumber": m["serial"],
                           "ManufactureYear": m["year"], "ManufactureWeek": m["week"],
                           "SMBIOSMemoryType": {"DDR3": 24, "DDR4": 26, "DDR5": 34}.get(m["type"])} for m in spd]
    elif not spd and is_root and any(to_int(m.get("FormFactor")) in (8, 12) for m in data["memory"]):
        errors["spd"] = ("даты изготовления модулей не прочитаны: не загружен драйвер SPD "
                         "(для DDR4 — sudo modprobe ee1004, для DDR5 — sudo modprobe spd5118, затем запустите снова)")

    os_release = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', lread("/etc/os-release") or "", re.M))
    uptime = to_int((lread("/proc/uptime") or "0").split(".")[0])
    cmdline = lread("/proc/cmdline") or ""
    data["os"] = [{
        "Caption": os_release.get("PRETTY_NAME") or os_release.get("NAME") or "Linux",
        "Kernel": platform.release(),
        "OSArchitecture": "64-разрядная" if platform.architecture()[0] == "64bit" else "32-разрядная",
        "LastBootUpTime": (dt.datetime.now() - dt.timedelta(seconds=uptime)).strftime("%Y-%m-%dT%H:%M:%S") if uptime else None,
        "LiveSession": any(k in cmdline for k in ("boot=casper", "boot=live", "rd.live.image", "archisobasedir")),
        "TotalVisibleMemorySize": to_int(mem.get("MemTotal")), "FreePhysicalMemory": to_int(mem.get("MemAvailable")),
    }]

    ids_pci = guard("pci_ids", lambda: load_ids("pci"))
    if ids_pci is None and "pci_ids" not in errors and lexists("/sys/bus/pci/devices"):
        errors["pci_ids"] = "не найдена база pci.ids, поэтому у PCI-устройств показаны только коды"
    pci = guard("pci", lambda: linux_pci(ids_pci), [])
    usb = guard("usb", lambda: linux_usb(guard("usb_ids", lambda: load_ids("usb"))), [])
    pci_by_addr = {d["addr"]: d for d in pci}
    usb_by_name = {d["busname"]: d for d in usb}

    data["gpu"] = guard("gpu", lambda: linux_gpus(pci), [])
    edids, displays, monitor_ids, monitor_conns = guard("monitor_id", lambda: linux_displays(pci_by_addr), ({}, [], [], []))
    local["edid"], local["displays"] = edids, displays
    data["monitor_id"], data["monitor_conn"] = monitor_ids, monitor_conns
    disks, partitions, volumes, health, cdroms = guard("physdisk", lambda: linux_storage(is_root, errors), ([], [], [], [], []))
    data.update(physdisk=disks, partition=partitions, logicaldisk=volumes, disk_health=health, cdrom=cdroms)
    data["netadapter"], data["netconfig"] = guard("netadapter", lambda: linux_network(pci_by_addr, usb_by_name), ([], []))
    data["sound"] = guard("sound", lambda: linux_sound(pci, usb), [])
    data["keyboard"], data["mouse"] = guard("keyboard", linux_input, ([], []))
    data["usbctrl"] = [{"Name": d["name"], "Manufacturer": d["vendor"], "PNPDeviceID": d["pnp"]}
                       for d in pci if d["class"] >> 8 == 0x0C03]
    data["battery"], local["battery_ioctl"] = guard("battery", linux_batteries, ([], []))
    tpm = lread("/sys/class/tpm/tpm0/tpm_version_major")
    data["tpm"] = [{"SpecVersion": f"{tpm}.0", "IsEnabled_InitialValue": True}] if tpm else []

    pnp, drivers = [], []
    for d, is_usb in [(d, False) for d in pci] + [(d, True) for d in usb]:
        status = "OK" if d["driver"] or (is_usb and d["busname"].startswith("usb")) else "нет драйвера"
        pnp.append({"Name": d["name"], "PNPClass": d["class"] if is_usb else pci_pnp_class(d["class"]),
                    "Manufacturer": d["vendor"], "Status": status, "ConfigManagerErrorCode": 0,
                    "PNPDeviceID": d["pnp"], "Present": True})
        if d["driver"]:
            version = d.get("driver_version")
            drivers.append({"DeviceID": d["pnp"], "DriverVersion": " ".join(x for x in (d["driver"], version) if x)})
    data["pnp"], data["drivers"] = pnp, drivers

    local["firmware"] = "UEFI" if lexists("/sys/firmware/efi") else "Legacy BIOS"
    sb = lread("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", binary=True)
    local["secure_boot"] = bool(sb[4]) if sb and len(sb) >= 5 else None
    return {"platform": "linux", "collected_at": dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "duration": round(time.time() - started, 1), "python": sys.version.split()[0],
            "wmi": {"data": data, "errors": errors}, "local": local}


def collect_linux_elevated():
    """Собрать данные с правами root через sudo, а отчёт сохранить от имени пользователя."""
    cmd = ["sudo", sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)])
    print("Для полного отчёта нужны права root — sudo может спросить пароль.", file=sys.stderr)
    proc = subprocess.run(cmd + ["--collect-to", "-"], stdout=subprocess.PIPE)
    if proc.returncode != 0 or not proc.stdout:
        raise CollectError("не удалось получить права root через sudo")
    return json.loads(proc.stdout.decode("utf-8"))


# ---------------------------------------------------------------------------
# Справочники
# ---------------------------------------------------------------------------

CHASSIS_TYPES = {
    1: "другое", 2: "неизвестно", 3: "настольный", 4: "низкопрофильный настольный", 5: "Pizza Box",
    6: "Mini Tower", 7: "Tower", 8: "портативный", 9: "ноутбук", 10: "ноутбук", 11: "карманный",
    12: "док-станция", 13: "моноблок", 14: "субноутбук", 15: "компактный", 16: "Lunch Box",
    17: "основное шасси", 18: "шасси расширения", 19: "подшасси", 20: "шасси расширения шины",
    21: "периферийное шасси", 22: "шасси хранилища", 23: "стоечный", 24: "герметичный ПК",
    25: "многосистемное шасси", 26: "Compact PCI", 27: "Advanced TCA", 28: "блейд-сервер",
    29: "блейд-корзина", 30: "планшет", 31: "трансформер", 32: "планшет со съёмной клавиатурой",
    33: "IoT-шлюз", 34: "встраиваемый ПК", 35: "мини-ПК", 36: "Stick PC",
}

PC_SYSTEM_TYPES = {
    1: "настольный", 2: "мобильный (ноутбук)", 3: "рабочая станция", 4: "корпоративный сервер",
    5: "сервер SOHO", 6: "Appliance PC", 7: "высокопроизводительный сервер", 8: "планшет",
}

CPU_ARCH = {0: "x86", 1: "MIPS", 2: "Alpha", 3: "PowerPC", 5: "ARM", 6: "Itanium", 9: "x64", 12: "ARM64"}

CPU_VENDORS = {"GenuineIntel": "Intel", "AuthenticAMD": "AMD", "Qualcomm Technologies Inc": "Qualcomm"}

SMBIOS_MEMORY_TYPES = {
    3: "DRAM", 15: "SDRAM", 17: "RDRAM", 18: "DDR", 19: "DDR2", 20: "DDR2 FB-DIMM", 24: "DDR3",
    25: "FBD2", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3", 30: "LPDDR4",
    32: "HBM", 33: "HBM2", 34: "DDR5", 35: "LPDDR5", 36: "HBM3",
}
WMI_MEMORY_TYPES = {17: "SDRAM", 20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 25: "FBD2", 26: "DDR4"}
MEMORY_FORM_FACTORS = {8: "DIMM", 11: "RIMM", 12: "SO-DIMM", 13: "SRIMM", 21: "BGA (распаяна)"}

# Коды производителей памяти JEDEC JEP106 (так их часто отдаёт SMBIOS вместо названия)
JEDEC_VENDORS = {
    "80CE": "Samsung", "00CE": "Samsung", "CE00": "Samsung",
    "80AD": "SK hynix", "00AD": "SK hynix", "AD00": "SK hynix",
    "802C": "Micron", "002C": "Micron", "2C00": "Micron",
    "859B": "Crucial", "059B": "Crucial", "9B05": "Crucial",
    "0198": "Kingston", "9801": "Kingston",
    "029E": "Corsair", "9E02": "Corsair",
    "04CD": "G.Skill", "CD04": "G.Skill",
    "04CB": "ADATA", "CB04": "ADATA",
    "04EF": "Team Group", "EF04": "Team Group",
    "830B": "Nanya", "0B83": "Nanya",
}

PCI_VENDORS = {
    "10DE": "NVIDIA", "1002": "AMD", "1022": "AMD", "8086": "Intel", "1414": "Microsoft",
    "15AD": "VMware", "80EE": "VirtualBox", "1AF4": "Red Hat (virtio)", "1234": "QEMU",
    "5143": "Qualcomm", "1B36": "Red Hat (QEMU)", "102B": "Matrox", "1A03": "ASPEED",
}

# Поколение процессора по коду модели (CPUID): (название поколения, год выхода)
INTEL_CPU_MODELS = {
    0x2A: ("Sandy Bridge", "2011"), 0x2D: ("Sandy Bridge-E", "2011"), 0x3A: ("Ivy Bridge", "2012"),
    0x3E: ("Ivy Bridge-E", "2013"), 0x3C: ("Haswell", "2013"), 0x45: ("Haswell", "2013"), 0x46: ("Haswell", "2013"),
    0x3F: ("Haswell-E", "2014"), 0x3D: ("Broadwell", "2015"), 0x47: ("Broadwell", "2015"), 0x4F: ("Broadwell-E", "2016"),
    0x4E: ("Skylake", "2015"), 0x5E: ("Skylake", "2015"), 0x55: ("Skylake-X / Cascade Lake", "2017–2019"),
    0x8E: ("Kaby Lake / Whiskey Lake / Comet Lake", "2016–2019"), 0x9E: ("Kaby Lake / Coffee Lake", "2017–2019"),
    0x66: ("Cannon Lake", "2018"), 0x7D: ("Ice Lake", "2019"), 0x7E: ("Ice Lake", "2019"), 0x6A: ("Ice Lake-SP", "2021"),
    0xA5: ("Comet Lake", "2020"), 0xA6: ("Comet Lake", "2020"), 0x8C: ("Tiger Lake", "2020"),
    0x8D: ("Tiger Lake-H", "2021"), 0xA7: ("Rocket Lake", "2021"), 0x97: ("Alder Lake", "2021"),
    0x9A: ("Alder Lake", "2022"), 0xBE: ("Alder Lake-N", "2023"), 0xB7: ("Raptor Lake", "2022"),
    0xBA: ("Raptor Lake", "2023"), 0xBF: ("Raptor Lake", "2023"), 0x8F: ("Sapphire Rapids", "2023"),
    0xCF: ("Emerald Rapids", "2023"), 0xAA: ("Meteor Lake", "2023"), 0xAC: ("Meteor Lake", "2023"),
    0xBD: ("Lunar Lake", "2024"), 0xC5: ("Arrow Lake", "2024"), 0xC6: ("Arrow Lake", "2024"),
    0xB5: ("Arrow Lake", "2025"), 0x37: ("Bay Trail", "2013"), 0x4C: ("Cherry Trail / Braswell", "2015"),
    0x5C: ("Apollo Lake", "2016"), 0x7A: ("Gemini Lake", "2017"), 0x96: ("Elkhart Lake", "2021"),
    0x9C: ("Jasper Lake", "2021"),
}
AMD_CPU_MODELS = {
    (0x17, 0x01): ("Zen (Summit Ridge)", "2017"), (0x17, 0x08): ("Zen+ (Pinnacle Ridge)", "2018"),
    (0x17, 0x11): ("Zen (Raven Ridge)", "2018"), (0x17, 0x18): ("Zen+ (Picasso)", "2019"),
    (0x17, 0x20): ("Zen (Dali)", "2020"), (0x17, 0x31): ("Zen 2 (Rome / Castle Peak)", "2019"),
    (0x17, 0x60): ("Zen 2 (Renoir)", "2020"), (0x17, 0x68): ("Zen 2 (Lucienne)", "2021"),
    (0x17, 0x71): ("Zen 2 (Matisse)", "2019"), (0x17, 0x90): ("Zen 2 (Van Gogh)", "2022"),
    (0x17, 0xA0): ("Zen 2 (Mendocino)", "2022"), (0x19, 0x01): ("Zen 3 (Milan)", "2021"),
    (0x19, 0x21): ("Zen 3 (Vermeer)", "2020"), (0x19, 0x40): ("Zen 3+ (Rembrandt)", "2022"),
    (0x19, 0x44): ("Zen 3+ (Rembrandt)", "2023"), (0x19, 0x50): ("Zen 3 (Cezanne / Barcelo)", "2021"),
    (0x19, 0x11): ("Zen 4 (Genoa)", "2022"), (0x19, 0x61): ("Zen 4 (Raphael)", "2022"),
    (0x19, 0x74): ("Zen 4 (Phoenix)", "2023"), (0x19, 0x75): ("Zen 4 (Phoenix / Hawk Point)", "2023–2024"),
    (0x19, 0x78): ("Zen 4 (Phoenix 2)", "2023"), (0x1A, 0x24): ("Zen 5 (Strix Point)", "2024"),
    (0x1A, 0x44): ("Zen 5 (Granite Ridge)", "2024"),
}
AMD_CPU_FAMILIES = {0x17: ("Zen / Zen+ / Zen 2", "2017–2022"), 0x19: ("Zen 3 / Zen 4", "2020–2024"),
                    0x1A: ("Zen 5", "2024–2025")}

# Архитектура видеочипа по коду устройства: (производитель, от, до, архитектура, годы выхода)
GPU_ARCHITECTURES = [
    ("10DE", 0x0FC0, 0x12FF, "Kepler", "2012–2014"), ("10DE", 0x1340, 0x17FF, "Maxwell", "2014–2016"),
    ("10DE", 0x1B00, 0x1DFF, "Pascal", "2016–2017"), ("10DE", 0x1E00, 0x1FFF, "Turing", "2018–2019"),
    ("10DE", 0x2180, 0x21FF, "Turing", "2019"), ("10DE", 0x2000, 0x20FF, "Ampere", "2020"),
    ("10DE", 0x2200, 0x22FF, "Ampere", "2020–2021"), ("10DE", 0x2300, 0x23FF, "Hopper", "2022"),
    ("10DE", 0x2400, 0x25FF, "Ampere", "2020–2021"), ("10DE", 0x2600, 0x28FF, "Ada Lovelace", "2022–2023"),
    ("10DE", 0x2900, 0x2FFF, "Blackwell", "2024–2025"),
    ("1002", 0x67C0, 0x67FF, "Polaris", "2016–2017"), ("1002", 0x6980, 0x699F, "Polaris", "2017"),
    ("1002", 0x6860, 0x687F, "Vega", "2017"), ("1002", 0x66A0, 0x66AF, "Vega 20", "2018–2019"),
    ("1002", 0x7310, 0x734F, "RDNA 1", "2019"), ("1002", 0x73A0, 0x73FF, "RDNA 2", "2020–2021"),
    ("1002", 0x7420, 0x743F, "RDNA 2", "2022"), ("1002", 0x7440, 0x749F, "RDNA 3", "2022–2023"),
    ("1002", 0x7500, 0x75FF, "RDNA 4", "2025"),
    ("1002", 0x15DD, 0x15DD, "Vega (Raven Ridge)", "2018"), ("1002", 0x15D8, 0x15D8, "Vega (Picasso)", "2019"),
    ("1002", 0x1636, 0x1636, "Vega (Renoir)", "2020"), ("1002", 0x1638, 0x1638, "Vega (Cezanne)", "2021"),
    ("1002", 0x164C, 0x164C, "Vega (Lucienne)", "2021"), ("1002", 0x1681, 0x1681, "RDNA 2 (Rembrandt)", "2022"),
    ("1002", 0x164E, 0x164E, "RDNA 2 (Raphael)", "2022"), ("1002", 0x163F, 0x163F, "RDNA 2 (Van Gogh)", "2022"),
    ("1002", 0x1506, 0x1506, "RDNA 2 (Mendocino)", "2022"), ("1002", 0x15BF, 0x15BF, "RDNA 3 (Phoenix)", "2023"),
    ("1002", 0x15C8, 0x15C8, "RDNA 3 (Phoenix 2)", "2023"), ("1002", 0x150E, 0x150E, "RDNA 3.5 (Strix Point)", "2024"),
    ("1002", 0x13C0, 0x13C0, "RDNA 2 (Granite Ridge)", "2024"),
    ("8086", 0x5690, 0x56BF, "Arc Alchemist", "2022"), ("8086", 0xE200, 0xE2FF, "Arc Battlemage", "2024"),
]


def cpu_generation(cpu):
    m = re.search(r"Family (\d+) Model (\d+)", str(cpu.get("Caption") or ""))
    if not m:
        return None
    family, model = int(m.group(1)), int(m.group(2))
    vendor = str(cpu.get("Manufacturer") or "")
    if "Intel" in vendor and family == 6:
        gen = INTEL_CPU_MODELS.get(model)
    elif "AMD" in vendor:
        gen = AMD_CPU_MODELS.get((family, model)) or AMD_CPU_FAMILIES.get(family)
    else:
        gen = None
    return f"{gen[0]}, {gen[1]}" if gen else None


def gpu_architecture(pnp_id):
    ids = hw_ids(pnp_id) if pnp_id and "VEN_" in str(pnp_id).upper() else None
    if not ids:
        return None
    vendor, device = ids.split(":")
    for ven, lo, hi, arch, years in GPU_ARCHITECTURES:
        if ven == vendor and lo <= int(device, 16) <= hi:
            return f"{arch}, {years}"
    return None


def made_text(year, week=None):
    """«8-я неделя 2020 г.» или «2020 г.»."""
    year, week = to_int(year), to_int(week)
    if not year:
        return None
    return f"{week}-я неделя {year} г." if week and 1 <= week <= 53 else f"{year} г."


MONITOR_VENDORS = {
    "ACI": "ASUS", "ACR": "Acer", "AOC": "AOC", "APP": "Apple", "AUO": "AU Optronics", "AUS": "ASUS",
    "BNQ": "BenQ", "BOE": "BOE", "CMN": "Innolux", "CMO": "Chi Mei", "CSO": "CSOT", "DEL": "Dell",
    "EIZ": "EIZO", "ENC": "EIZO", "GBT": "Gigabyte", "GSM": "LG", "HKC": "HKC", "HPN": "HP", "HWP": "HP",
    "HSD": "HannStar", "HWV": "Huawei", "IVM": "iiyama", "IVO": "InfoVision", "LEN": "Lenovo",
    "LGD": "LG Display", "LPL": "LG Philips", "MEI": "Panasonic", "MSI": "MSI", "NEC": "NEC",
    "PHL": "Philips", "SAM": "Samsung", "SDC": "Samsung Display", "SHP": "Sharp", "SNY": "Sony",
    "TSB": "Toshiba", "VSC": "ViewSonic", "XMI": "Xiaomi",
}

VIDEO_OUTPUTS = {
    0: "VGA (D-Sub)", 1: "S-Video", 2: "композитный", 3: "компонентный", 4: "DVI", 5: "HDMI",
    6: "LVDS (встроенный экран)", 8: "D-Jpn", 9: "SDI", 10: "DisplayPort",
    11: "eDP (встроенный экран)", 12: "UDI", 13: "UDI (встроенный)", 14: "SDTV",
    15: "Miracast (беспроводной)", 16: "непрямое подключение", 2147483648: "внутреннее подключение",
    4294967295: "другое", -1: "другое",
}

DISK_MEDIA_TYPES = {3: "HDD", 4: "SSD", 5: "SCM"}
DISK_BUS_TYPES = {
    1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "IEEE 1394", 5: "SSA", 6: "Fibre Channel", 7: "USB", 8: "RAID",
    9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "виртуальный", 15: "виртуальный (файл)",
    16: "Storage Spaces", 17: "NVMe", 18: "SCM", 19: "UFS",
}
DISK_HEALTH = {0: "исправен", 1: "предупреждение", 2: "неисправен", 5: "неизвестно"}

GPT_TYPES = {
    "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}": "системный (EFI)",
    "{e3c9e316-0b5c-4db8-817d-f92df00215ae}": "зарезервированный (MSR)",
    "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}": "основной",
    "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}": "восстановление",
    "{5808c8aa-7e8f-42e0-85d2-e1e90434cfb3}": "метаданные LDM",
    "{af9b60a0-1431-4f62-bc68-3311714a69ad}": "данные LDM",
    "{e75caf8f-f680-4cee-afa3-b001e56efc2d}": "Storage Spaces",
    "{0fc63daf-8483-4772-8e79-3d69d8477de4}": "Linux",
    "{0657fd6d-a4ab-43c4-84e5-0933c84b4f4f}": "Linux swap",
}
MBR_TYPES = {1: "FAT12", 4: "FAT16", 5: "расширенный", 6: "FAT16", 7: "NTFS/exFAT", 11: "FAT32",
             12: "FAT32", 14: "FAT16", 15: "расширенный", 39: "восстановление", 130: "Linux swap",
             131: "Linux", 238: "защитный GPT", 239: "системный (EFI)"}

DRIVE_TYPES = {2: "съёмный", 3: "локальный", 4: "сетевой", 5: "оптический", 6: "RAM-диск"}

NET_STATUS = {
    0: "отключён", 1: "подключается", 2: "подключён", 3: "отключается", 4: "оборудование отсутствует",
    5: "оборудование отключено", 6: "неисправность оборудования", 7: "кабель не подключён",
    8: "проверка подлинности", 9: "проверка пройдена", 10: "ошибка проверки подлинности",
    11: "неверный адрес", 12: "требуются учётные данные",
}

BATTERY_STATUS = {
    1: "разряжается", 2: "питание от сети", 3: "полностью заряжена", 4: "низкий заряд",
    5: "критический заряд", 6: "заряжается", 7: "заряжается", 8: "заряжается", 9: "заряжается",
    11: "частично заряжена",
}
BATTERY_CHEMISTRY = {3: "свинцово-кислотная", 4: "никель-кадмиевая", 5: "никель-металлгидридная",
                     6: "литий-ионная", 7: "цинк-воздушная", 8: "литий-полимерная"}

CM_ERRORS = {
    1: "устройство неправильно настроено", 3: "драйвер повреждён или не хватает памяти",
    10: "устройство не может запуститься", 12: "не хватает свободных ресурсов",
    14: "нужна перезагрузка", 18: "нужно переустановить драйвер", 19: "ошибка в реестре",
    21: "устройство удаляется", 22: "устройство отключено", 24: "устройство отсутствует или неисправно",
    28: "драйвер не установлен", 29: "отключено в прошивке (BIOS/UEFI)", 31: "не удалось загрузить драйвер",
    32: "служба драйвера отключена", 37: "драйвер вернул ошибку", 38: "предыдущий драйвер ещё в памяти",
    39: "драйвер повреждён или отсутствует", 41: "драйвер загружен, но устройство не найдено",
    43: "устройство сообщило о неполадке (код 43)", 45: "устройство не подключено",
    47: "подготовлено к безопасному извлечению", 48: "драйвер заблокирован",
    52: "не удалось проверить цифровую подпись драйвера",
}

PNP_CLASSES = {
    "AudioEndpoint": "Аудиовходы и аудиовыходы", "Battery": "Батареи", "Biometric": "Биометрические устройства",
    "Bluetooth": "Bluetooth", "Camera": "Камеры", "CDROM": "DVD и CD-дисководы", "Computer": "Компьютер",
    "DiskDrive": "Дисковые устройства", "Display": "Видеоадаптеры", "Extension": "Расширения",
    "Firmware": "Встроенное ПО", "HDC": "Контроллеры IDE ATA/ATAPI", "HIDClass": "Устройства HID",
    "Image": "Устройства обработки изображений", "Infrared": "Инфракрасные устройства",
    "Keyboard": "Клавиатуры", "MEDIA": "Звуковые, игровые и видеоустройства", "Modem": "Модемы",
    "Monitor": "Мониторы", "Mouse": "Мыши и иные указывающие устройства", "MTD": "Устройства памяти MTD",
    "Net": "Сетевые адаптеры", "Ports": "Порты (COM и LPT)", "Printer": "Принтеры",
    "PrintQueue": "Очереди печати", "Processor": "Процессоры", "SCSIAdapter": "Контроллеры запоминающих устройств",
    "SDHost": "Хост-адаптеры SD", "SecurityDevices": "Устройства безопасности", "Sensor": "Датчики",
    "SmartCardReader": "Устройства чтения смарт-карт", "SoftwareComponent": "Программные компоненты",
    "SoftwareDevice": "Программные устройства", "System": "Системные устройства",
    "USB": "Контроллеры USB", "USBDevice": "Устройства USB", "Volume": "Тома",
    "VolumeSnapshot": "Теневые копии томов", "WPD": "Переносные устройства",
    "WSDPrintDevice": "Сетевые принтеры (WSD)", "UCM": "Коннекторы USB Type-C",
    "SmartCard": "Смарт-карты", "Media": "Мультимедиа",
}

JUNK_VALUES = {
    "to be filled by o.e.m.", "to be filled by oem", "to be filled", "default string", "default",
    "not applicable", "not specified", "not available", "not defined", "none", "n/a", "na", "unknown",
    "unknow", "undefined", "invalid", "empty", "system serial number", "system product name",
    "system manufacturer", "system version", "system sku", "sku", "base board serial number",
    "base board product name", "chassis serial number", "chassis manufacture", "chassis version",
    "o.e.m.", "oem", "x.x", "type1productconfigid", "123456789", "1234567890", "0123456789",
    "serial number", "asset tag", "asset-1234567890", "no asset tag", "no asset information",
    "no enclosure", "sernum0", "partnum0",
}


# ---------------------------------------------------------------------------
# Форматирование значений
# ---------------------------------------------------------------------------

def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def to_int(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d+\s*", value):
        return int(value)
    return None


def clean(value):
    """Строка без лишних пробелов; заглушки вроде «To Be Filled By O.E.M.» -> None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v not in (None, ""))
    s = re.sub(r"\s+", " ", str(value).replace("\x00", " ")).strip()
    if not s or s.casefold() in JUNK_VALUES:
        return None
    if re.fullmatch(r"[0\-_. ]+|[Ff\-]{8,}", s):
        return None
    return s


def fnum(value, digits=1):
    s = f"{value:.{digits}f}"
    if digits:
        s = s.rstrip("0").rstrip(".")
    return s.replace(".", ",")


def fint(value):
    return f"{value:,}".replace(",", " ")


UNITS = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"]


def fbytes(value, digits=1):
    n = to_int(value)
    if n is None or n < 0:
        return None
    v, i = float(n), 0
    while v >= 1024 and i < len(UNITS) - 1:
        v /= 1024
        i += 1
    return f"{fnum(v, digits if i else 0)} {UNITS[i]}"


def fdisk_size(value):
    """Объём накопителя: как в Windows и как на коробке (десятичные гигабайты)."""
    n = to_int(value)
    if not n:
        return None
    if n < 1e9:
        return fbytes(n)
    label = f"{fnum(n / 1e12, 2)} ТБ" if n >= 1e12 else f"{round(n / 1e9)} ГБ"
    return f"{fbytes(n)} ({label} по маркировке)"


def fspeed(bps):
    n = to_int(bps)
    if not n or n >= 2 ** 62:
        return None
    if n >= 1e9:
        return f"{fnum(n / 1e9, 1)} Гбит/с"
    return f"{fnum(n / 1e6, 1)} Мбит/с"


def fbool(value, yes="да", no="нет"):
    if value is None:
        return None
    return yes if value else no


def ru_plural(n, forms):
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return forms[0]
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return forms[1]
    return forms[2]


def parse_dt(value):
    if not value or not isinstance(value, str):
        return None
    m = re.match(r"/Date\((-?\d+)", value)
    if m:
        return dt.datetime(1970, 1, 1) + dt.timedelta(milliseconds=int(m.group(1)))
    m = re.match(r"(\d{4})-?(\d{2})-?(\d{2})(?:[T ]?(\d{2}):?(\d{2}):?(\d{2}))?", value.strip())
    if not m:
        return None
    try:
        parts = [int(x) if x else 0 for x in m.groups()]
        return dt.datetime(*parts)
    except ValueError:
        return None


def fdate(value):
    d = parse_dt(value) if not isinstance(value, dt.datetime) else value
    return d.strftime("%d.%m.%Y") if d and d.year > 1970 else None


def fdatetime(value):
    d = parse_dt(value) if not isinstance(value, dt.datetime) else value
    return d.strftime("%d.%m.%Y %H:%M") if d and d.year > 1970 else None


def fduration(delta):
    minutes = int(delta.total_seconds() // 60)
    if minutes < 0:
        return None
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    parts = ([f"{days} д"] if days else []) + ([f"{hours} ч"] if hours or days else []) + [f"{mins} мин"]
    return " ".join(parts)


def hw_ids(pnp_id):
    """VID:PID для USB/HID или VEN:DEV для PCI из идентификатора устройства."""
    if not pnp_id:
        return None
    m = re.search(r"VID_([0-9A-F]{4}).*?PID_([0-9A-F]{4})", pnp_id, re.I)
    if not m:
        m = re.search(r"VEN_([0-9A-F]{4}).*?DEV_([0-9A-F]{4})", pnp_id, re.I)
    return f"{m.group(1).upper()}:{m.group(2).upper()}" if m else None


def memory_vendor(raw):
    name = clean(raw)
    if not name:
        return None
    code = re.sub(r"[^0-9A-F]", "", name.upper())
    if code == name.upper() and len(code) >= 4:
        vendor = JEDEC_VENDORS.get(code[:4])
        return f"{vendor} ({name})" if vendor else name
    return name


def wmi_string(value):
    """WmiMonitorID хранит строки как массивы кодов символов."""
    chars = [to_int(c) for c in as_list(value)]
    return clean("".join(chr(c) for c in chars if c)) if chars else None


def norm_instance(name):
    if not name:
        return None
    return re.sub(r"_\d+$", "", str(name)).upper()


def parse_edid(hexstr):
    try:
        b = bytes.fromhex(hexstr or "")
    except ValueError:
        return {}
    if len(b) < 128 or b[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return {}
    info = {}
    code = (b[8] << 8) | b[9]
    info["vendor"] = "".join(chr(((code >> s) & 0x1F) + 64) for s in (10, 5, 0))
    info["product"] = f"{b[10] | (b[11] << 8):04X}"
    if b[17]:
        info["year"] = 1990 + b[17]
        if 1 <= b[16] <= 53:
            info["week"] = b[16]
    if b[21] and b[22]:
        info["size_mm"] = (b[21] * 10, b[22] * 10)
    for off in (54, 72, 90, 108):
        d = b[off:off + 18]
        clock = d[0] | (d[1] << 8)
        if clock:
            if "native" in info:
                continue
            ha, hb = d[2] | ((d[4] & 0xF0) << 4), d[3] | ((d[4] & 0x0F) << 8)
            va, vb = d[5] | ((d[7] & 0xF0) << 4), d[6] | ((d[7] & 0x0F) << 8)
            if ha and va:
                info["native"] = (ha, va)
                total = (ha + hb) * (va + vb)
                if total:
                    info["native_hz"] = clock * 10000 / total
                wmm, hmm = d[12] | ((d[14] & 0xF0) << 4), d[13] | ((d[14] & 0x0F) << 8)
                if 0 < wmm < 5000 and 0 < hmm < 5000:
                    info["size_mm"] = (wmm, hmm)
            continue
        text = d[5:18].split(b"\x0a")[0].decode("cp437", errors="replace").strip()
        if d[3] == 0xFC and text:
            info["name"] = text
        elif d[3] == 0xFF and text:
            info["serial"] = text
        elif d[3] == 0xFE and text:
            info.setdefault("texts", []).append(text)
    # У матриц ноутбуков модель обычно лежит в строке 0xFE: «AUO» + «B156HAN08.4»
    models = [t for t in info.get("texts", []) if re.search(r"\d", t) and len(t) >= 5]
    if models:
        info["panel"] = models[-1]
    return info


# ---------------------------------------------------------------------------
# Модель отчёта
# ---------------------------------------------------------------------------

class KV:
    """Блок «параметр — значение»."""
    kind = "kv"

    def __init__(self, title=None):
        self.title = title
        self.rows = []  # [label, value, sensitive]

    def add(self, label, value, sensitive=False):
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value if v not in (None, ""))
        if value is None:
            return self
        value = str(value).strip()
        if value:
            self.rows.append([label, value, sensitive])
        return self


class Table:
    """Табличный блок."""
    kind = "table"

    def __init__(self, title, columns, sensitive=(), collapsible=False, masked=()):
        self.title = title
        self.columns = list(columns)
        self.sensitive = set(sensitive)
        self.masked = set(masked)  # столбцы, где при --anon прячутся только MAC-адреса
        self.collapsible = collapsible
        self.rows = []

    def add(self, *cells):
        self.rows.append(["" if c is None else str(c) for c in cells])


class Section:
    def __init__(self, sid, title):
        self.id = sid
        self.title = title
        self.blocks = []
        self.notes = []

    def kv(self, title=None):
        block = KV(title)
        self.blocks.append(block)
        return block

    def table(self, title, columns, sensitive=(), collapsible=False, masked=()):
        block = Table(title, columns, sensitive, collapsible, masked)
        self.blocks.append(block)
        return block

    def is_empty(self):
        return not any(b.rows for b in self.blocks) and not self.notes


class Report:
    def __init__(self, computer, generated):
        self.title = "Сведения об оборудовании компьютера"
        self.computer = computer
        self.generated = generated
        self.sections = []


MAC_IN_ID = re.compile(r"(?<![0-9A-F])[0-9A-F]{12}(?![0-9A-F])", re.I)


def anonymize(report):
    report.computer = HIDDEN
    for sec in report.sections:
        for block in sec.blocks:
            if block.kind == "kv":
                for row in block.rows:
                    if row[2]:
                        row[1] = HIDDEN
            else:
                idx = [i for i, c in enumerate(block.columns) if c in block.sensitive]
                masked = [i for i, c in enumerate(block.columns) if c in block.masked]
                for row in block.rows:
                    for i in idx:
                        if row[i]:
                            row[i] = HIDDEN
                    for i in masked:
                        row[i] = MAC_IN_ID.sub("XXXXXXXXXXXX", row[i])


# ---------------------------------------------------------------------------
# Построение разделов отчёта
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, raw):
        wmi = raw.get("wmi") or {}
        self.data = wmi.get("data") or {}
        self.errors = wmi.get("errors") or {}
        self.local = raw.get("local") or {}
        self.collected_at = parse_dt(raw.get("collected_at")) or dt.datetime.now()
        self.platform = raw.get("platform") or "windows"
        self.facts = OrderedDict()
        self.checks = []  # (что проверено, вывод) для раздела «Проверка состояния»
        self.dates = []  # (компонент, дата текстом, год, неделя) — даты изготовления экземпляров
        self.battery_complete = False
        self.battery_noted = False
        self._drivers = None

    def rows(self, key):
        return [r for r in as_list(self.data.get(key)) if isinstance(r, dict)]

    def first(self, key):
        rows = self.rows(key)
        return rows[0] if rows else {}

    def driver(self, pnp_id):
        if self._drivers is None:
            self._drivers = {str(d.get("DeviceID")).upper(): d for d in self.rows("drivers") if d.get("DeviceID")}
        return self._drivers.get(str(pnp_id or "").upper(), {})

    def driver_text(self, pnp_id, with_provider=False):
        d = self.driver(pnp_id)
        version = clean(d.get("DriverVersion"))
        if not version:
            return None
        text = version
        date = fdate(d.get("DriverDate"))
        if date:
            text += f" от {date}"
        provider = clean(d.get("DriverProviderName"))
        if with_provider and provider:
            text += f", {provider}"
        return text

    def pnp(self):
        # HTREE\ROOT\0 — служебный корень дерева устройств; Диспетчер устройств его не показывает
        return [d for d in self.rows("pnp") if d.get("Present") is not False
                and not str(d.get("PNPDeviceID") or "").upper().startswith("HTREE\\")]


def verdict(items):
    """Итог проверки: самый серьёзный значок и пояснения. items = [(0 норма | 1 внимание | 2 неисправность, текст)]."""
    if not items:
        return None
    return {0: "✔", 1: "⚠", 2: "✖"}[max(level for level, _ in items)] + " " + "; ".join(t for _, t in items)


def admin_hint(ctx):
    return "запустите через sudo" if ctx.platform == "linux" else "запустите от имени администратора"


def detect_vm(manufacturer, model):
    s = f"{manufacturer or ''} {model or ''}".lower()
    for needle, name in (("vmware", "VMware"), ("virtualbox", "VirtualBox"), ("innotek", "VirtualBox"),
                         ("qemu", "QEMU/KVM"), ("kvm", "QEMU/KVM"), ("parallels", "Parallels"),
                         ("xen", "Xen"), ("virtual machine", "Hyper-V")):
        if needle in s:
            return name
    return None


def build_system(ctx):
    cs, prod, enc = ctx.first("system"), ctx.first("product"), ctx.first("enclosure")
    sec = Section("system", "Компьютер")
    kv = sec.kv()
    manufacturer = clean(cs.get("Manufacturer")) or clean(prod.get("Vendor"))
    model = clean(cs.get("Model")) or clean(prod.get("Name"))
    version = clean(prod.get("Version"))
    if manufacturer and manufacturer.upper() == "LENOVO" and version and model and version != model:
        model = f"{version} ({model})"  # у Lenovo понятное название модели лежит в Version
        version = None
    chassis = [CHASSIS_TYPES.get(to_int(c)) for c in as_list(enc.get("ChassisTypes"))]
    chassis = ", ".join(OrderedDict.fromkeys(c for c in chassis if c)) or None
    if cs.get("PartOfDomain"):
        domain_label, domain = "Домен", clean(cs.get("Domain"))
    else:
        domain_label, domain = "Рабочая группа", clean(cs.get("Workgroup")) or clean(cs.get("Domain"))
    vm = detect_vm(manufacturer, model)

    kv.add("Имя компьютера", clean(cs.get("Name")), sensitive=True)
    kv.add("Производитель", manufacturer)
    kv.add("Модель", model)
    kv.add("Семейство", clean(cs.get("SystemFamily")))
    kv.add("Версия", version)
    kv.add("SKU", clean(cs.get("SystemSKUNumber")))
    kv.add("Тип корпуса", chassis)
    kv.add("Тип ПК", PC_SYSTEM_TYPES.get(to_int(cs.get("PCSystemType"))))
    kv.add("Платформа", clean(cs.get("SystemType")))
    kv.add("Виртуальная машина", vm)
    kv.add("Серийный номер", clean(prod.get("IdentifyingNumber")) or clean(enc.get("SerialNumber")), sensitive=True)
    kv.add("UUID", clean(prod.get("UUID")), sensitive=True)
    kv.add("Инвентарный номер", clean(enc.get("SMBIOSAssetTag")), sensitive=True)
    kv.add(domain_label, domain, sensitive=True)
    kv.add("Пользователь", clean(cs.get("UserName")), sensitive=True)

    name = " ".join(x for x in (manufacturer, model) if x)
    if name:
        ctx.facts["Компьютер"] = name + (f" ({chassis})" if chassis else "") + (f", виртуальная машина {vm}" if vm else "")
    return sec


def build_os(ctx):
    os_ = ctx.first("os")
    sec = Section("os", "Операционная система")
    kv = sec.kv()
    caption = clean(os_.get("Caption"))
    display_version = clean(ctx.local.get("display_version"))
    version = clean(os_.get("Version"))
    ubr = to_int(ctx.local.get("ubr"))
    if version and ubr:
        version = f"{version}.{ubr}"
    boot = parse_dt(os_.get("LastBootUpTime"))
    uptime = fduration(ctx.collected_at - boot) if boot else None

    kv.add("Система", caption)
    kv.add("Выпуск", display_version)
    kv.add("Версия (сборка)", version)
    kv.add("Ядро Linux", clean(os_.get("Kernel")))
    kv.add("Запуск", "Live-система с загрузочной флешки" if os_.get("LiveSession") else None)
    kv.add("Разрядность", clean(os_.get("OSArchitecture")))
    kv.add("Установлена", fdatetime(os_.get("InstallDate")))
    kv.add("Последняя загрузка", fdatetime(boot) + (f" (работает {uptime})" if uptime else "") if boot else None)
    kv.add("Зарегистрированный пользователь", clean(os_.get("RegisteredUser")), sensitive=True)
    kv.add("Организация", clean(os_.get("Organization")), sensitive=True)

    if caption:
        build = clean(os_.get("BuildNumber"))
        text = caption + (f" {display_version}" if display_version else "")
        details = [x for x in ((f"сборка {build}" + (f".{ubr}" if ubr else "")) if build else None,
                               clean(os_.get("OSArchitecture"))) if x]
        ctx.facts["Операционная система"] = text + (f" ({', '.join(details)})" if details else "")
    return sec


def build_bios(ctx):
    b = ctx.first("bios")
    sec = Section("bios", "BIOS / UEFI")
    kv = sec.kv()
    firmware = ctx.local.get("firmware")
    secure_boot = ctx.local.get("secure_boot")
    smbios = None
    if to_int(b.get("SMBIOSMajorVersion")) is not None:
        smbios = f"{b.get('SMBIOSMajorVersion')}.{b.get('SMBIOSMinorVersion') or 0}"
    ec_major = to_int(b.get("EmbeddedControllerMajorVersion"))
    ec = f"{ec_major}.{to_int(b.get('EmbeddedControllerMinorVersion')) or 0}" if ec_major not in (None, 255) else None

    kv.add("Производитель", clean(b.get("Manufacturer")))
    kv.add("Версия", clean(b.get("SMBIOSBIOSVersion")) or clean(b.get("Version")))
    kv.add("Дата выпуска", fdate(b.get("ReleaseDate")))
    kv.add("Режим загрузки", firmware)
    kv.add("Secure Boot", None if secure_boot is None else fbool(secure_boot, "включён", "выключен"))
    kv.add("Версия SMBIOS", smbios)
    kv.add("Встроенный контроллер (EC)", ec)
    kv.add("Серийный номер", clean(b.get("SerialNumber")), sensitive=True)

    parts = [x for x in (clean(b.get("Manufacturer")), clean(b.get("SMBIOSBIOSVersion"))) if x]
    if parts:
        extra = [x for x in (fdate(b.get("ReleaseDate")), firmware,
                             "Secure Boot включён" if secure_boot else None) if x]
        ctx.facts["BIOS"] = " ".join(parts) + (f" ({', '.join(extra)})" if extra else "")
    return sec


def build_baseboard(ctx):
    bb = ctx.first("baseboard")
    sec = Section("baseboard", "Материнская плата")
    kv = sec.kv()
    kv.add("Производитель", clean(bb.get("Manufacturer")))
    kv.add("Модель", clean(bb.get("Product")))
    kv.add("Ревизия", clean(bb.get("Version")))
    kv.add("Серийный номер", clean(bb.get("SerialNumber")), sensitive=True)
    name = " ".join(x for x in (clean(bb.get("Manufacturer")), clean(bb.get("Product"))) if x)
    if name:
        ctx.facts["Материнская плата"] = name
    return sec


def build_cpu(ctx):
    cpus = ctx.rows("cpu")
    hypervisor = ctx.first("system").get("HypervisorPresent")
    sec = Section("cpu", "Процессор")
    names = []
    for i, c in enumerate(cpus, 1):
        kv = sec.kv(f"Процессор {i}" if len(cpus) > 1 else None)
        name = clean(c.get("Name"))
        cores, enabled, threads = (to_int(c.get("NumberOfCores")), to_int(c.get("NumberOfEnabledCore")),
                                   to_int(c.get("NumberOfLogicalProcessors")))
        max_mhz, cur_mhz = to_int(c.get("MaxClockSpeed")), to_int(c.get("CurrentClockSpeed"))
        l2, l3 = to_int(c.get("L2CacheSize")), to_int(c.get("L3CacheSize"))
        vendor = clean(c.get("Manufacturer"))

        if hypervisor and ctx.platform == "linux":
            virt = "система запущена внутри виртуальной машины"
        elif hypervisor:
            virt = "включена (работает гипервизор Hyper-V/VBS)"
        else:
            virt = fbool(c.get("VirtualizationFirmwareEnabled"), "включена в BIOS/UEFI", "выключена в BIOS/UEFI")
        kv.add("Модель", name)
        kv.add("Производитель", CPU_VENDORS.get(vendor, vendor))
        if cores:
            kv.add("Ядра / потоки", f"{cores} / {threads}" if threads else cores)
        if enabled and cores and enabled != cores:
            kv.add("Включено ядер", enabled)
        kv.add("Базовая частота", f"{fnum(max_mhz / 1000, 2)} ГГц" if max_mhz else None)
        turbo = to_int(c.get("MaxTurboMHz"))
        if turbo and (not max_mhz or turbo > max_mhz + 50):
            kv.add("Максимальная частота (турбо)", f"{fnum(turbo / 1000, 2)} ГГц")
        if cur_mhz and max_mhz and abs(cur_mhz - max_mhz) > 50:
            kv.add("Текущая частота", f"{fnum(cur_mhz / 1000, 2)} ГГц")
        kv.add("Кэш L2", fbytes(l2 * 1024) if l2 else None)
        kv.add("Кэш L3", fbytes(l3 * 1024) if l3 else None)
        kv.add("Сокет", clean(c.get("SocketDesignation")))
        kv.add("Архитектура", CPU_ARCH.get(to_int(c.get("Architecture"))))
        kv.add("Разрядность", f"{c.get('AddressWidth')} бит" if to_int(c.get("AddressWidth")) else None)
        kv.add("Поколение (год выхода модели)", cpu_generation(dict(c, Manufacturer=CPU_VENDORS.get(vendor, vendor))))
        kv.add("Семейство / модель / степпинг", clean(c.get("Caption")))
        kv.add("ID процессора (CPUID)", clean(c.get("ProcessorId")))
        kv.add("Аппаратная виртуализация", virt)
        kv.add("Поддержка SLAT", fbool(c.get("SecondLevelAddressTranslationExtensions")))
        if name:
            desc = name
            if cores:
                desc += f", {cores} {ru_plural(cores, ('ядро', 'ядра', 'ядер'))}"
                if threads:
                    desc += f" / {threads} {ru_plural(threads, ('поток', 'потока', 'потоков'))}"
            names.append(desc)
    if names:
        ctx.facts["Процессор"] = "; ".join(names) if len(names) == 1 else f"{len(names)} × " + names[0]
    return sec


def memory_type(m):
    t = SMBIOS_MEMORY_TYPES.get(to_int(m.get("SMBIOSMemoryType")))
    return t or WMI_MEMORY_TYPES.get(to_int(m.get("MemoryType")))


def build_memory(ctx):
    mods = ctx.rows("memory")
    arrays = [a for a in ctx.rows("memarray") if to_int(a.get("Use")) in (3, None)]
    cs, os_ = ctx.first("system"), ctx.first("os")
    sec = Section("memory", "Оперативная память")
    kv = sec.kv()

    total = sum(to_int(m.get("Capacity")) or 0 for m in mods)
    slots = sum(to_int(a.get("MemoryDevices")) or 0 for a in arrays)
    max_kb = sum((to_int(a.get("MaxCapacityEx")) or to_int(a.get("MaxCapacity")) or 0) for a in arrays)
    types = list(OrderedDict.fromkeys(t for t in (memory_type(m) for m in mods) if t))
    speeds = sorted({to_int(m.get("Speed")) for m in mods if to_int(m.get("Speed"))})
    configured = sorted({to_int(m.get("ConfiguredClockSpeed")) for m in mods if to_int(m.get("ConfiguredClockSpeed"))})
    ecc = any((to_int(m.get("TotalWidth")) or 0) > (to_int(m.get("DataWidth")) or 0) > 0 for m in mods)
    visible_kb = to_int(os_.get("TotalVisibleMemorySize"))
    free_kb = to_int(os_.get("FreePhysicalMemory"))

    kv.add("Всего установлено", fbytes(total) if total else None)
    kv.add("Доступно Windows" if ctx.platform == "windows" else "Доступно системе",
           fbytes(visible_kb * 1024) if visible_kb else fbytes(cs.get("TotalPhysicalMemory")))
    kv.add("Свободно сейчас", fbytes(free_kb * 1024) if free_kb else None)
    kv.add("Тип", ", ".join(types) or None)
    if speeds:
        speed_text = ", ".join(str(s) for s in speeds) + " МТ/с"
        if configured and configured != speeds:
            speed_text += f" (работает на {', '.join(str(s) for s in configured)} МТ/с)"
        kv.add("Скорость", speed_text)
    if slots:
        kv.add("Слоты", f"занято {len(mods)} из {slots}")
    kv.add("Максимальный объём (по данным платы)", fbytes(max_kb * 1024) if max_kb else None)
    kv.add("ECC", "да" if ecc else None)

    table = sec.table("Модули памяти", ["Слот", "Объём", "Тип", "Скорость", "Напряжение",
                                        "Производитель", "Партномер", "Дата изготовления", "Серийный номер"],
                      sensitive=["Серийный номер"])
    for m in mods:
        slot = clean(m.get("DeviceLocator"))
        bank = clean(m.get("BankLabel"))
        if bank and slot and bank != slot:
            slot = f"{slot} ({bank})"
        mtype = " ".join(x for x in (memory_type(m), MEMORY_FORM_FACTORS.get(to_int(m.get("FormFactor")))) if x)
        speed, conf = to_int(m.get("Speed")), to_int(m.get("ConfiguredClockSpeed"))
        speed_text = f"{speed} МТ/с" if speed else ""
        if conf and speed and conf != speed:
            speed_text += f" (сейчас {conf})"
        mv = to_int(m.get("ConfiguredVoltage"))
        table.add(slot or bank, fbytes(m.get("Capacity")), mtype, speed_text,
                  f"{fnum(mv / 1000, 3)} В" if mv else "", memory_vendor(m.get("Manufacturer")),
                  clean(m.get("PartNumber")), made_text(m.get("ManufactureYear"), m.get("ManufactureWeek")),
                  clean(m.get("SerialNumber")))
        made = made_text(m.get("ManufactureYear"), m.get("ManufactureWeek"))
        if made:
            label = f"модуль памяти {mods.index(m) + 1}" if len(mods) > 1 else "память"
            ctx.dates.append((label, made, to_int(m.get("ManufactureYear")), to_int(m.get("ManufactureWeek")) or 0))

    items = []
    slow = [(to_int(m.get("ConfiguredClockSpeed")), to_int(m.get("Speed"))) for m in mods
            if to_int(m.get("ConfiguredClockSpeed")) and to_int(m.get("Speed"))
            and to_int(m.get("ConfiguredClockSpeed")) < to_int(m.get("Speed"))]
    if slow:
        items.append((1, f"память работает на {slow[0][0]} МТ/с вместо паспортных {slow[0][1]}"))
    if len(mods) == 1 and slots >= 2:
        items.append((1, "установлен один модуль: память работает в одноканальном режиме, это медленнее"))
    if mods and not items:
        items.append((0, f"{fbytes(total)}, {len(mods)} {ru_plural(len(mods), ('модуль', 'модуля', 'модулей'))}, "
                         "без замечаний"))
    if not mods and ctx.platform == "linux" and ctx.local.get("is_admin") is False:
        items.append((1, f"модули памяти не видны — {admin_hint(ctx)}"))
    if items:
        ctx.checks.append(("Оперативная память", verdict(items)))

    if total or visible_kb:
        text = fbytes(total) if total else fbytes(visible_kb * 1024)
        if types:
            text += " " + "/".join(types) + (f"-{speeds[-1]}" if speeds else "")
        sizes = Counter(to_int(m.get("Capacity")) for m in mods if to_int(m.get("Capacity")))
        if sizes:
            text += " (" + " + ".join(f"{n} × {fbytes(s)}" if n > 1 else fbytes(s) for s, n in sizes.items())
            text += f", занято слотов {len(mods)} из {slots})" if slots else ")"
        ctx.facts["Оперативная память"] = text
    return sec


def gpu_registry_entries(gpu, registry):
    name = (clean(gpu.get("Name")) or "").casefold()
    pnp = (gpu.get("PNPDeviceID") or "").lower()
    candidates = [e for e in registry or [] if (e.get("name") or "").casefold() == name]
    if len(candidates) > 1 and pnp:
        candidates = [e for e in candidates if (e.get("matching_id") or "").lower() in pnp] or candidates
    return candidates


def gpu_vram(gpu, registry):
    for e in gpu_registry_entries(gpu, registry):
        size = to_int(e.get("memory"))
        if size and size > 0:
            return fbytes(size)
    ram = to_int(gpu.get("AdapterRAM"))
    if ram and ram > 0:
        if ram >= 0xFFF00000:
            return "4 ГБ или больше (точнее WMI не сообщает)"
        return fbytes(ram)
    return None


def build_gpu(ctx):
    gpus = ctx.rows("gpu")
    registry = ctx.local.get("gpu_registry") or []
    sec = Section("gpu", "Видеокарты")
    summary = []
    for i, g in enumerate(gpus, 1):
        kv = sec.kv(f"Видеоадаптер {i}" if len(gpus) > 1 else None)
        name = clean(g.get("Name"))
        pnp = g.get("PNPDeviceID")
        vram = fbytes(g.get("VRAM")) if to_int(g.get("VRAM")) else gpu_vram(g, registry)
        ids = hw_ids(pnp)
        vendor = clean(g.get("AdapterCompatibility"))
        if not vendor and ids:
            vendor = PCI_VENDORS.get(ids.split(":")[0])
        w, h = to_int(g.get("CurrentHorizontalResolution")), to_int(g.get("CurrentVerticalResolution"))
        mode = None
        if w and h:
            mode = f"{w}×{h}"
            if to_int(g.get("CurrentRefreshRate")):
                mode += f", {g.get('CurrentRefreshRate')} Гц"
            if to_int(g.get("CurrentBitsPerPixel")):
                mode += f", {g.get('CurrentBitsPerPixel')} бит"
        driver = clean(g.get("DriverVersion"))
        if driver and fdate(g.get("DriverDate")):
            driver += f" от {fdate(g.get('DriverDate'))}"
        status = clean(g.get("Status"))

        kv.add("Модель", name)
        kv.add("Производитель", vendor)
        kv.add("Видеопроцессор", clean(g.get("VideoProcessor")))
        kv.add("Архитектура (год выхода модели)", gpu_architecture(pnp))
        kv.add("Видеопамять", vram)
        kv.add("Текущий режим", mode)
        kv.add("Драйвер", driver)
        bios = clean(g.get("VideoBios")) or next((clean(e.get("bios")) for e in gpu_registry_entries(g, registry)
                                                  if clean(e.get("bios"))), None)
        kv.add("BIOS видеокарты", bios)
        kv.add("Серийный номер", clean(g.get("SerialNumber")), sensitive=True)
        kv.add("ID оборудования (VEN:DEV)", ids)
        if status and status.upper() != "OK":
            kv.add("Состояние", status)
        if name:
            summary.append(name + (f" ({vram})" if vram and "WMI" not in vram else ""))
    if summary:
        ctx.facts["Видеокарта" if len(summary) == 1 else "Видеокарты"] = "; ".join(summary)
    return sec


GENERIC_MONITOR_NAMES = {"generic pnp monitor", "generic non-pnp monitor", "универсальный монитор pnp",
                         "универсальный монитор не pnp", "default monitor", "монитор по умолчанию"}
INTERNAL_OUTPUTS = {6, 11, 13, 2147483648}  # LVDS, eDP, встроенный UDI, внутреннее подключение


def build_monitors(ctx):
    sec = Section("monitors", "Мониторы")
    edids = ctx.local.get("edid") or {}
    displays = ctx.local.get("displays") or []
    modes = {d.get("instance"): d for d in displays if d.get("instance")}
    params = {norm_instance(p.get("InstanceName")): p for p in ctx.rows("monitor_params")}
    conns = {norm_instance(p.get("InstanceName")): p for p in ctx.rows("monitor_conn")}

    entries = [(norm_instance(m.get("InstanceName")), m) for m in ctx.rows("monitor_id") if m.get("Active") is not False]
    if not entries:  # WMI недоступен — берём то, что знает WinAPI
        entries = [(d.get("instance"), {}) for d in displays]

    summary = []
    for i, (key, m) in enumerate(entries, 1):
        e = parse_edid(edids.get(key)) if key else {}
        mode = modes.get(key) or (displays[i - 1] if not modes and i <= len(displays) else {})
        p, c = params.get(key, {}), conns.get(key, {})

        vendor_code = wmi_string(m.get("ManufacturerName")) or e.get("vendor")
        vendor = MONITOR_VENDORS.get((vendor_code or "").upper())
        product = wmi_string(m.get("ProductCodeID")) or e.get("product")
        name = wmi_string(m.get("UserFriendlyName")) or e.get("name")
        serial = wmi_string(m.get("SerialNumberID")) or e.get("serial")
        panel = e.get("panel")
        tech = to_int(c.get("VideoOutputTechnology"))
        if not name or name.casefold() in GENERIC_MONITOR_NAMES:
            model = " ".join(x for x in (vendor or vendor_code, panel) if x)
            if tech in INTERNAL_OUTPUTS:
                name = "Встроенный экран" + (f" {model}" if model else "")
            else:
                name = model or clean(mode.get("monitor"))

        size_mm = e.get("size_mm")
        if not size_mm and to_int(p.get("MaxHorizontalImageSize")) and to_int(p.get("MaxVerticalImageSize")):
            size_mm = (to_int(p.get("MaxHorizontalImageSize")) * 10, to_int(p.get("MaxVerticalImageSize")) * 10)
        diag = None
        if size_mm:
            inches = math.hypot(*size_mm) / 25.4
            diag = f"{fnum(inches, 1)}″ ({fnum(size_mm[0] / 10, 1)}×{fnum(size_mm[1] / 10, 1)} см)"
        native = None
        if e.get("native"):
            native = f"{e['native'][0]}×{e['native'][1]}"
            if e.get("native_hz"):
                native += f", {round(e['native_hz'])} Гц"
        current = None
        if mode.get("width"):
            current = f"{mode['width']}×{mode['height']}"
            if mode.get("frequency") and mode["frequency"] > 1:
                current += f", {mode['frequency']} Гц"
            if mode.get("bpp"):
                current += f", {mode['bpp']} бит"
        year = to_int(m.get("YearOfManufacture")) or e.get("year")
        week = to_int(m.get("WeekOfManufacture")) or e.get("week")
        made = None
        if year:
            made = f"{week}-я неделя {year} г." if week and 1 <= week <= 53 else f"{year} г."

        kv = sec.kv(f"Монитор {i}" if len(entries) > 1 else None)
        kv.add("Модель", name)
        kv.add("Производитель", f"{vendor} ({vendor_code})" if vendor else vendor_code)
        kv.add("Модель матрицы", panel)
        kv.add("Код модели", f"{vendor_code or ''}{product or ''}" or None)
        kv.add("Диагональ (по EDID)", diag)
        kv.add("Родное разрешение", native)
        kv.add("Текущий режим", current)
        kv.add("Основной монитор", "да" if mode.get("primary") else None)
        kv.add("Подключение", VIDEO_OUTPUTS.get(tech) if tech is not None else None)
        kv.add("Видеоадаптер", clean(mode.get("adapter")))
        kv.add("Дата выпуска", made)
        kv.add("Серийный номер", serial, sensitive=True)
        if year:
            ctx.dates.append(("экран", made, year, week if week and 1 <= week <= 53 else 0))
        label = name or " ".join(x for x in (vendor or vendor_code, product) if x)
        if label:
            extra = [x for x in (diag.split(" ")[0] if diag else None, native) if x]
            summary.append(label + (f" ({', '.join(extra)})" if extra else ""))
    if summary:
        ctx.facts["Монитор" if len(summary) == 1 else "Мониторы"] = "; ".join(summary)
    return sec


def drive_letter(value):
    if isinstance(value, int):
        value = chr(value) if value else ""
    s = str(value or "").strip("\x00 ").upper()
    return s if len(s) == 1 and s.isalpha() else None


def build_storage(ctx):
    sec = Section("storage", "Накопители")
    disks = ctx.rows("physdisk")
    parts = ctx.rows("partition")
    health = {str(h.get("DeviceId")): h for h in ctx.rows("disk_health")}
    for did, nvme in (ctx.local.get("nvme_health") or {}).items():  # журнал NVMe дополняет счётчики Windows
        counters = {k: v for k, v in health.get(str(did), {}).items() if v is not None}
        health[str(did)] = dict({k: v for k, v in nvme.items() if k != "Health"}, **counters)
    letters_by_disk = {}
    disk_by_letter = {}
    for p in parts:
        letter = drive_letter(p.get("DriveLetter"))
        if letter:
            letters_by_disk.setdefault(str(p.get("DiskNumber")), []).append(f"{letter}:")
            disk_by_letter[f"{letter}:"] = str(p.get("DiskNumber"))
        elif clean(p.get("MountPoint")):
            letters_by_disk.setdefault(str(p.get("DiskNumber")), []).append(clean(p.get("MountPoint")))

    summary = []
    disk_names = {}
    if disks:
        for d in sorted(disks, key=lambda x: to_int(x.get("DeviceId")) or 0):
            did = str(d.get("DeviceId"))
            name = clean(d.get("FriendlyName")) or clean(d.get("Model")) or f"Диск {did}"
            disk_names[did] = name
            media = DISK_MEDIA_TYPES.get(to_int(d.get("MediaType")))
            bus = DISK_BUS_TYPES.get(to_int(d.get("BusType")))
            if not media and bus == "NVMe":
                media = "SSD"
            kind = ", ".join(x for x in (media, bus) if x) or None
            rpm = to_int(d.get("SpindleSpeed"))
            h = health.get(did, {})
            temp, temp_max = to_int(h.get("Temperature")), to_int(h.get("TemperatureMax"))
            hours = to_int(h.get("PowerOnHours"))
            errors = [(to_int(h.get("ReadErrorsUncorrected")) or 0), (to_int(h.get("WriteErrorsUncorrected")) or 0)]
            serial = clean(d.get("SerialNumber"))

            kv = sec.kv(f"Диск {did}: {name}")
            kv.add("Модель", name)
            kv.add("Тип", kind)
            kv.add("Объём", fdisk_size(d.get("Size")))
            kv.add("Скорость вращения", f"{rpm} об/мин" if rpm and 0 < rpm < 100000 else None)
            kv.add("Прошивка", clean(d.get("FirmwareVersion")))
            kv.add("Серийный номер", serial.rstrip(".") if serial else None, sensitive=True)
            kv.add("Состояние", DISK_HEALTH.get(to_int(d.get("HealthStatus"))))
            if temp:
                kv.add("Температура", f"{temp} °C" + (f" (максимум {temp_max} °C)" if temp_max else ""))
            if to_int(h.get("Wear")) is not None and (to_int(h.get("Wear")) or media == "SSD"):
                kv.add("Износ (израсходованный ресурс)", f"{h.get('Wear')} %")
            if hours:
                kv.add("Наработка", f"{fint(hours)} ч (≈{fnum(hours / 24 / 365, 1)} г.)")
            if to_int(h.get("StartStopCycleCount")):
                kv.add("Циклов включения", fint(to_int(h.get("StartStopCycleCount"))))
            written = to_int(h.get("DataWrittenBytes"))
            kv.add("Записано за всё время", fbytes(written) if written else None)
            if any(errors):
                kv.add("Неисправленные ошибки чтения / записи", f"{errors[0]} / {errors[1]}")
            for field, label in (("ReallocatedSectors", "Переназначенные сектора"),
                                 ("PendingSectors", "Нестабильные сектора"), ("UnsafeShutdowns", "Аварийных отключений")):
                if to_int(h.get(field)) is not None:
                    kv.add(label, fint(to_int(h.get(field))))
            if to_int(h.get("CriticalWarning")):
                kv.add("Критическое предупреждение SMART", f"да (код {h.get('CriticalWarning')})")
            kv.add("Тома", ", ".join(sorted(letters_by_disk.get(did, []))) or None)

            items = []
            state = to_int(d.get("HealthStatus"))
            if state == 2:
                items.append((2, "SMART сообщает о неисправности"))
            elif state == 1 or to_int(h.get("CriticalWarning")):
                items.append((2, "SMART выдаёт критическое предупреждение"))
            elif state == 0:
                items.append((0, "состояние: исправен"))
            problems = [(errors[0] + errors[1], ("неисправленная ошибка", "неисправленные ошибки", "неисправленных ошибок")),
                        (to_int(h.get("ReallocatedSectors")) or 0, ("переназначенный сектор", "переназначенных сектора",
                                                                    "переназначенных секторов")),
                        (to_int(h.get("PendingSectors")) or 0, ("нестабильный сектор", "нестабильных сектора",
                                                                "нестабильных секторов"))]
            for n, forms in problems:
                if n:
                    items.append((2, f"{n} {ru_plural(n, forms)}"))
            if hours is not None:
                if hours <= 50:
                    items.append((0, f"наработка {hours} ч — диск новый"))
                elif hours <= 500:
                    items.append((1, f"наработка {fint(hours)} ч — диском уже пользовались"))
                else:
                    items.append((1, f"наработка {fint(hours)} ч (≈{fint(round(hours / 24))} дн.) — диск явно не новый"))
            if written:
                used = written > 200e9
                items.append((1 if used else 0, f"записано {fbytes(written)}" + (" — диском уже пользовались" if used else "")))
            wear = to_int(h.get("Wear"))
            if wear is not None and (wear or media == "SSD"):
                items.append((1 if wear >= 10 else 0, f"износ {wear} %"))
            if not h and state is None and bus in ("USB", "виртуальный"):
                pass  # у флешек и виртуальных дисков SMART обычно нет — не о чем предупреждать
            elif not h and state is not None and ctx.local.get("is_admin") is False:
                items.append((1, f"наработка и износ не видны — {admin_hint(ctx)}"))
            elif not h and state is None:
                if ctx.local.get("is_admin") is False:
                    items.append((1, f"нет данных SMART — {admin_hint(ctx)}"))
                else:
                    items.append((1, "нет данных SMART"))
            if items:
                ctx.checks.append((f"Диск {did}: {name}", verdict(items)))

            size = to_int(d.get("Size"))
            if size:
                short = f"{fnum(size / 1e12, 2)} ТБ" if size >= 1e12 else f"{round(size / 1e9)} ГБ"
                summary.append(f"{name} ({', '.join(x for x in (short, kind) if x)})")
    else:  # запасной вариант для систем без пространства имён Storage
        for d in sorted(ctx.rows("diskdrive"), key=lambda x: to_int(x.get("Index")) or 0):
            did = str(d.get("Index"))
            name = clean(d.get("Model")) or f"Диск {did}"
            disk_names[did] = name
            kv = sec.kv(f"Диск {did}: {name}")
            kv.add("Модель", name)
            kv.add("Интерфейс", clean(d.get("InterfaceType")))
            kv.add("Тип носителя", clean(d.get("MediaType")))
            kv.add("Объём", fdisk_size(d.get("Size")))
            kv.add("Прошивка", clean(d.get("FirmwareRevision")))
            kv.add("Серийный номер", clean(d.get("SerialNumber")), sensitive=True)
            kv.add("Разделов", to_int(d.get("Partitions")))
            kv.add("Состояние", clean(d.get("Status")))
            size = to_int(d.get("Size"))
            if size:
                summary.append(f"{name} ({round(size / 1e9)} ГБ)")

    if parts:
        where = "Точка монтирования" if ctx.platform == "linux" else "Буква"
        table = sec.table("Разделы", ["Диск", "Раздел", where, "Назначение", "Файловая система", "Метка", "Размер"])
        for p in sorted(parts, key=lambda x: (to_int(x.get("DiskNumber")) or 0, to_int(x.get("PartitionNumber")) or 0)):
            purpose = GPT_TYPES.get(str(p.get("GptType") or "").lower()) or MBR_TYPES.get(to_int(p.get("MbrType")))
            flags = [x for x in ("системный" if p.get("IsSystem") and "EFI" not in (purpose or "") else None,
                                 "загрузочный" if p.get("IsBoot") else None) if x]
            if flags:
                purpose = f"{purpose or 'раздел'} ({', '.join(flags)})"
            letter = drive_letter(p.get("DriveLetter"))
            table.add(p.get("DiskNumber"), p.get("PartitionNumber"), f"{letter}:" if letter else clean(p.get("MountPoint")),
                      purpose, clean(p.get("FileSystem")), clean(p.get("Label")), fbytes(p.get("Size")))

    volumes = ctx.rows("logicaldisk")
    if volumes:
        table = sec.table("Логические диски", ["Точка монтирования" if ctx.platform == "linux" else "Диск", "Метка",
                                               "Файловая система", "Объём", "Свободно", "Тип", "Физический диск"])
        for v in sorted(volumes, key=lambda x: str(x.get("DeviceID"))):
            size, free = to_int(v.get("Size")), to_int(v.get("FreeSpace"))
            free_text = fbytes(free) if free is not None else ""
            if size and free is not None:
                free_text += f" ({round(free * 100 / size)} %)"
            dev = str(v.get("DeviceID") or "")
            phys = disk_by_letter.get(dev.upper()) or (str(v["DiskNumber"]) if v.get("DiskNumber") is not None else None)
            kind = DRIVE_TYPES.get(to_int(v.get("DriveType")), "")
            if to_int(v.get("DriveType")) == 4 and clean(v.get("ProviderName")):
                kind += f": {clean(v.get('ProviderName'))}"
            table.add(dev, clean(v.get("VolumeName")), clean(v.get("FileSystem")), fbytes(size),
                      free_text, kind, f"Диск {phys} ({disk_names[phys]})" if phys in disk_names else "")

    if summary:
        ctx.facts["Накопители"] = "; ".join(summary)
    return sec


VIRTUAL_NET_PREFIXES = ("ROOT\\", "SWD\\", "BTH\\", "{", "COMPOSITEBUS\\", "TAP")


def build_network(ctx):
    sec = Section("network", "Сетевые адаптеры")
    configs = {to_int(c.get("Index")): c for c in ctx.rows("netconfig")}
    summary = []
    adapters = [a for a in ctx.rows("netadapter")
                if not str(a.get("PNPDeviceID") or "").upper().startswith(VIRTUAL_NET_PREFIXES)]
    for a in sorted(adapters, key=lambda x: (to_int(x.get("NetConnectionStatus")) != 2, str(x.get("Name")))):
        name = clean(a.get("Name"))
        lname = (name or "").lower()
        if any(w in lname for w in ("wi-fi", "wifi", "wireless", "wlan", "802.11", "беспровод")):
            kind = "Wi-Fi"
        elif "bluetooth" in lname:
            kind = "Bluetooth"
        else:
            kind = clean(a.get("AdapterType"))
            if kind and "802.3" in kind:
                kind = "Ethernet"
        status_code = to_int(a.get("NetConnectionStatus"))
        status = NET_STATUS.get(status_code)
        if status_code == 7 and kind != "Ethernet":
            status = "не подключён к сети"
        cfg = configs.get(to_int(a.get("Index")), {})
        ips = [str(ip) for ip in as_list(cfg.get("IPAddress"))]

        kv = sec.kv(clean(a.get("NetConnectionID")) or name)
        kv.add("Адаптер", name)
        kv.add("Производитель", clean(a.get("Manufacturer")))
        kv.add("Тип", kind)
        kv.add("MAC-адрес", clean(a.get("MACAddress")), sensitive=True)
        kv.add("Состояние", status)
        if status_code == 2:
            kv.add("Скорость подключения", fspeed(a.get("Speed")))
        kv.add("IPv4", [ip for ip in ips if "." in ip], sensitive=True)
        kv.add("IPv6", [ip for ip in ips if ":" in ip], sensitive=True)
        kv.add("Шлюз", as_list(cfg.get("DefaultIPGateway")), sensitive=True)
        kv.add("DNS-серверы", as_list(cfg.get("DNSServerSearchOrder")), sensitive=True)
        if cfg:
            kv.add("DHCP", fbool(cfg.get("DHCPEnabled"), "включён", "выключен"))
        kv.add("Драйвер", ctx.driver_text(a.get("PNPDeviceID"), with_provider=True))
        kv.add("ID оборудования", hw_ids(a.get("PNPDeviceID")))
        if name:
            summary.append(name)
    if summary:
        ctx.facts["Сеть"] = "; ".join(summary)
    return sec


def build_audio(ctx):
    sec = Section("audio", "Звук")
    names = []
    devices = ctx.rows("sound")
    for i, s in enumerate(devices, 1):
        name = clean(s.get("Name"))
        kv = sec.kv(f"Звуковое устройство {i}" if len(devices) > 1 else None)
        kv.add("Устройство", name)
        kv.add("Производитель", clean(s.get("Manufacturer")))
        kv.add("Аудиокодеки", as_list(s.get("Codecs")))
        kv.add("Драйвер", ctx.driver_text(s.get("PNPDeviceID"), with_provider=True))
        kv.add("ID оборудования", hw_ids(s.get("PNPDeviceID")))
        status = clean(s.get("Status"))
        if status and status.upper() != "OK":
            kv.add("Состояние", status)
        if name:
            names.append(name)
    endpoints = sorted({clean(d.get("Name")) for d in ctx.pnp() if d.get("PNPClass") == "AudioEndpoint"} - {None})
    if endpoints:
        table = sec.table("Аудиовходы и аудиовыходы", ["Устройство"])
        for name in endpoints:
            table.add(name)
    if names:
        ctx.facts["Звук"] = "; ".join(names)
    return sec


def build_input(ctx):
    sec = Section("input", "Устройства ввода")
    kbd = ctx.rows("keyboard")
    if kbd:
        table = sec.table("Клавиатуры", ["Название", "Описание", "VID:PID"])
        for k in kbd:
            table.add(clean(k.get("Name")), clean(k.get("Description")), hw_ids(k.get("PNPDeviceID")))
    mice = ctx.rows("mouse")
    if mice:
        table = sec.table("Мыши, тачпады и другие указывающие устройства", ["Название", "Производитель", "VID:PID"])
        for m in mice:
            table.add(clean(m.get("Name")), clean(m.get("Manufacturer")), hw_ids(m.get("PNPDeviceID")))
    return sec


PNP_STATUSES = {
    "ok": "работает", "error": "ошибка", "degraded": "работает с ограничениями",
    "unknown": "состояние неизвестно", "pred fail": "ожидается сбой", "starting": "запускается",
    "stopping": "останавливается", "service": "обслуживается", "stressed": "перегружено",
    "nonrecover": "неустранимая ошибка", "no contact": "нет связи", "lost comm": "связь потеряна",
}


def has_no_driver(ctx, device):
    """Устройство из группы «Другие устройства»: Windows не нашла для него драйвер."""
    return not device.get("PNPClass") and not ctx.driver_text(device.get("PNPDeviceID"))


def pnp_status(ctx, device):
    code = to_int(device.get("ConfigManagerErrorCode"))
    if code:
        return CM_ERRORS.get(code, f"ошибка (код {code})")
    if has_no_driver(ctx, device):
        return "драйвер не установлен"
    status = str(device.get("Status") or "").strip()
    return PNP_STATUSES.get(status.lower(), status) if status else "работает"


# Стандартные службы Bluetooth: 16-битный код из UUID вида {0000XXXX-0000-1000-8000-00805F9B34FB}
BT_BASE_UUID = re.compile(r"\{0000([0-9A-F]{4})-0000-1000-8000-00805F9B34FB\}", re.I)
BT_SERVICES = {
    "1101": "последовательный порт (SPP)", "1103": "удалённый доступ к сети (DUN)",
    "1105": "передача файлов (OBEX)", "1106": "передача файлов (FTP)", "1108": "гарнитура (HSP)",
    "110A": "источник звука (A2DP)", "110B": "приёмник звука (A2DP)", "110C": "пульт управления (AVRCP)",
    "110E": "пульт управления (AVRCP)", "110F": "пульт управления (AVRCP)", "1112": "шлюз гарнитуры (HSP)",
    "1115": "личная сеть (PAN)", "1116": "точка доступа (NAP)", "111E": "громкая связь (HFP)",
    "111F": "шлюз громкой связи (HFP)", "1124": "устройство ввода (HID)", "112F": "телефонная книга (PBAP)",
    "1132": "сообщения (MAP)", "1133": "уведомления о сообщениях (MAP)", "1134": "сообщения (MAP)",
    "1200": "сведения об устройстве (PnP)", "1800": "общий доступ (GAP)", "1801": "общие атрибуты (GATT)",
    "180A": "сведения об устройстве", "180F": "уровень заряда батареи", "1812": "устройство ввода (HID)",
    "FE2C": "Google Fast Pair", "FE95": "служба Xiaomi",
}

# Служебные каналы Bluetooth-наушников, которые Windows показывает как неизвестные устройства
DEVICE_NAME_HINTS = [
    (r"airoha", "канал наушников (чип Airoha) для приложения на телефоне; драйвер не нужен"),
    (r"^ota\d*$", "канал обновления прошивки Bluetooth-устройства; драйвер не нужен"),
    (r"xiao ?ai", "канал голосового помощника Xiaomi «Сяо Ай»; драйвер не нужен"),
    (r"btnotify", "служба уведомлений Bluetooth-гарнитуры (MediaTek); драйвер не нужен"),
]


def device_hint(device):
    """Подсказка, что это за устройство: (текст, служебный ли это Bluetooth-канал)."""
    name = clean(device.get("Name")) or ""
    pid = str(device.get("PNPDeviceID") or "").upper()
    bluetooth = pid.startswith(("BTHENUM\\", "BTHLEDEVICE\\", "BTHLE\\", "BTHHFENUM\\"))
    for pattern, text in DEVICE_NAME_HINTS:
        if re.search(pattern, name, re.I):
            return text, True
    if bluetooth:
        m = BT_BASE_UUID.search(pid)
        if m and m.group(1) in BT_SERVICES:
            return f"служба Bluetooth «{BT_SERVICES[m.group(1)]}» сопряжённого устройства; драйвер обычно не нужен", True
        if "{" in pid:
            return "фирменная служба Bluetooth-устройства (наушников, телефона); драйвер не нужен", True
        return "сопряжённое Bluetooth-устройство", True
    ids = hw_ids(pid)
    if pid.startswith("ACPI\\"):
        acpi = pid.split("\\")[1] if pid.count("\\") else ""
        return f"устройство системной платы ({acpi}); драйвер — в разделе «Чипсет» на сайте производителя", False
    if pid.startswith("PCI\\"):
        vendor = PCI_VENDORS.get(ids.split(":")[0]) if ids else None
        return f"PCI-устройство {ids or ''}{f' ({vendor})' if vendor else ''}; драйвер ищется по коду VEN:DEV", False
    if pid.startswith(("USB\\", "HID\\")):
        return f"USB-устройство {ids or ''}; драйвер ищется по коду VID:PID", False
    if pid.startswith(("SWD\\", "ROOT\\")):
        return "программное устройство, созданное Windows или программой", False
    return None, False


def build_pnp_class(ctx, sid, title, classes, fact=None):
    devices = [d for d in ctx.pnp() if d.get("PNPClass") in classes]
    sec = Section(sid, title)
    if devices:
        table = sec.table(None, ["Устройство", "Производитель", "ID оборудования", "Драйвер", "Состояние"])
        for d in sorted(devices, key=lambda x: str(x.get("Name"))):
            table.add(clean(d.get("Name")), clean(d.get("Manufacturer")), hw_ids(d.get("PNPDeviceID")),
                      ctx.driver_text(d.get("PNPDeviceID")), pnp_status(ctx, d))
        if fact:
            ctx.facts[fact] = "; ".join(clean(d.get("Name")) or "?" for d in devices)
    return sec


def build_usb(ctx):
    sec = Section("usb", "USB")
    ctrls = ctx.rows("usbctrl")
    if ctrls:
        table = sec.table("Контроллеры USB", ["Контроллер", "Производитель", "Драйвер"])
        for c in ctrls:
            table.add(clean(c.get("Name")), clean(c.get("Manufacturer")), ctx.driver_text(c.get("PNPDeviceID")))
    devices = []
    for d in ctx.pnp():
        pid = str(d.get("PNPDeviceID") or "").upper()
        name = clean(d.get("Name")) or ""
        if not pid.startswith("USB\\") or "ROOT_HUB" in pid:
            continue
        if d.get("PNPClass") == "USB" and re.search(r"hub|концентратор", name, re.I):
            continue
        devices.append(d)
    if devices:
        table = sec.table("Подключённые USB-устройства", ["Устройство", "Класс", "VID:PID", "Производитель", "Состояние"])
        for d in sorted(devices, key=lambda x: str(x.get("Name"))):
            cls = d.get("PNPClass")
            table.add(clean(d.get("Name")), PNP_CLASSES.get(cls, cls), hw_ids(d.get("PNPDeviceID")),
                      clean(d.get("Manufacturer")), pnp_status(ctx, d))
    return sec


BATTERY_REPORT_CHEMISTRY = {"LION": "литий-ионная", "LI-ION": "литий-ионная", "LIP": "литий-полимерная",
                            "LIPO": "литий-полимерная", "PBAC": "свинцово-кислотная", "NICD": "никель-кадмиевая",
                            "NIMH": "никель-металлгидридная"}
# Служебные имена из ACPI-таблиц прошивки вместо модели батареи (например, BIF0_9)
ACPI_BATTERY_ID = re.compile(r"_?(BIF|BIX|BAT|BST|CMB)\d*(_\d+)?", re.I)


def build_battery(ctx):
    sec = Section("battery", "Батарея")
    batteries = ctx.rows("battery")
    static = ctx.rows("battery_static")
    full_rows = ctx.rows("battery_full")
    full = {b.get("InstanceName"): b for b in full_rows}
    cycles = {b.get("InstanceName"): b for b in ctx.rows("battery_cycles")}
    # Сведения от драйвера батареи, недостающее — из отчёта powercfg
    ioctl = [x for x in as_list(ctx.local.get("battery_ioctl")) if isinstance(x, dict)]
    powercfg = [x for x in as_list(ctx.local.get("battery_report")) if isinstance(x, dict)]
    reports = []
    for i in range(max(len(ioctl), len(powercfg))):
        a = ioctl[i] if i < len(ioctl) else {}
        p = powercfg[i] if i < len(powercfg) else {}
        reports.append({k: a.get(k) if a.get(k) not in (None, "", 0) else p.get(k) for k in set(a) | set(p)})
    laptop = to_int(ctx.first("system").get("PCSystemType")) == 2
    count = max(len(batteries), len(static), len(reports))
    ctx.battery_complete = count > 0
    summary = []
    for i in range(count):
        b = batteries[i] if i < len(batteries) else {}
        s = static[i] if i < len(static) else {}
        r = reports[i] if i < len(reports) else {}
        inst = s.get("InstanceName")
        f = full.get(inst) or (full_rows[i] if not inst and i < len(full_rows) else {})
        c = cycles.get(inst, {})
        # Источники по убыванию надёжности: root/wmi, отчёт powercfg, Win32_Battery
        designed = to_int(s.get("DesignedCapacity")) or to_int(r.get("design")) or to_int(b.get("DesignCapacity"))
        current = (to_int(f.get("FullChargedCapacity")) or to_int(r.get("full"))
                   or to_int(b.get("FullChargeCapacity")))
        cycle_count = to_int(c.get("CycleCount")) or to_int(r.get("cycles"))
        charge = to_int(b.get("EstimatedChargeRemaining"))
        runtime = to_int(b.get("EstimatedRunTime"))
        wear = max(0.0, 100 - current * 100 / designed) if designed and current else None
        if wear is None:
            ctx.battery_complete = False
            if r and not to_int(r.get("design")):
                sec.notes.append("Прошивка не сообщает Windows паспортную ёмкость батареи (драйвер батареи её "
                                 "не отдаёт), поэтому износ посчитать нельзя. Паспортная ёмкость указана на "
                                 "наклейке батареи и в характеристиках ноутбука; износ = 100 % − полная ёмкость "
                                 "сейчас ÷ паспортная × 100 %.")
                ctx.battery_noted = True

        raw_name = clean(s.get("DeviceName")) or clean(r.get("id")) or clean(b.get("Name"))
        placeholder = bool(raw_name and ACPI_BATTERY_ID.fullmatch(raw_name))
        manufacturer = clean(s.get("ManufactureName")) or clean(r.get("manufacturer"))
        if manufacturer and ACPI_BATTERY_ID.fullmatch(manufacturer):
            manufacturer = None
        name = raw_name
        if not raw_name or placeholder:
            name = "Встроенная батарея ноутбука" if laptop else "Батарея"
        chemistry = (BATTERY_CHEMISTRY.get(to_int(b.get("Chemistry")))
                     or BATTERY_REPORT_CHEMISTRY.get(str(r.get("chemistry") or "").upper()))

        kv = sec.kv(f"Батарея {i + 1}" if count > 1 else None)
        kv.add("Название", name)
        kv.add("Обозначение в прошивке", raw_name if placeholder else None)
        kv.add("Производитель", manufacturer)
        kv.add("Заряд", f"{charge} %" if charge is not None else None)
        kv.add("Состояние", BATTERY_STATUS.get(to_int(b.get("BatteryStatus"))))
        if runtime and runtime < 71582788:  # 71582788 — работа от сети
            kv.add("Оставшееся время", fduration(dt.timedelta(minutes=runtime)))
        kv.add("Химия", chemistry)
        # некоторые батареи сообщают ёмкость в мА·ч или в условных единицах
        unit = r.get("unit") or ("усл. ед." if r.get("relative") else "мВт·ч")
        kv.add("Паспортная ёмкость", f"{fint(designed)} {unit}" if designed else None)
        kv.add("Полная ёмкость сейчас", f"{fint(current)} {unit}" if current else None)
        if wear is not None:
            kv.add("Износ", f"{fnum(wear, 1)} % (осталось {fnum(100 - wear, 1)} % паспортной ёмкости)")
        kv.add("Циклов заряда", cycle_count or None)
        made = parse_dt(r.get("manufactured"))
        if made:
            kv.add("Дата изготовления", fdate(made))
            ctx.dates.append(("батарея", fdate(made), made.year, made.isocalendar()[1]))
        kv.add("Серийный номер", clean(s.get("SerialNumber")) or clean(r.get("serial")), sensitive=True)
        parts = [x for x in (f"заряд {charge} %" if charge is not None else None,
                             f"износ {fnum(wear, 1)} %" if wear is not None else None) if x]
        if parts:
            summary.append(", ".join(parts))

        items = []
        if wear is not None:
            w = fnum(wear, 1)
            if wear < 5:
                items.append((0, f"износ {w} % — как у новой"))
            elif wear < 15:
                items.append((1, f"износ {w} % — батарея уже немного поработала"))
            elif wear < 40:
                items.append((1, f"износ {w} % — батарея заметно изношена, у нового ноутбука так быть не должно"))
            else:
                items.append((2, f"износ {w} % — батарея сильно изношена"))
        else:
            items.append((1, "износ неизвестен: система не сообщила паспортную ёмкость"))
        if cycle_count:
            used = cycle_count > 10
            items.append((1 if used else 0, f"{cycle_count} {ru_plural(cycle_count, ('цикл', 'цикла', 'циклов'))} "
                                             "заряда" + (" — батарею уже активно использовали" if used else "")))
        ctx.checks.append((f"Батарея {i + 1}" if count > 1 else "Батарея", verdict(items)))
    if count and not ctx.battery_complete and not reports and (
            "battery_report" in ctx.local or "battery_ioctl" in ctx.local):
        sec.notes.append("Драйвер батареи не отдал сведения о ёмкости, поэтому износ посчитать нельзя.")
        ctx.battery_noted = True
    if summary:
        ctx.facts["Батарея"] = "; ".join(summary)
    return sec


VIRTUAL_PRINTER_PORTS = ("PORTPROMPT:", "NUL:", "SHRFAX:", "XPSPORT:")


def build_printers(ctx):
    sec = Section("printers", "Принтеры")
    real, virtual = [], []
    for p in ctx.rows("printer"):
        port = str(p.get("PortName") or "").upper()
        name = clean(p.get("Name")) or ""
        if port in VIRTUAL_PRINTER_PORTS or port.startswith("ONENOTE") or re.search(r"PDF|XPS|OneNote|Fax|Факс", name, re.I):
            virtual.append(name)
        else:
            real.append(p)
    if real:
        table = sec.table(None, ["Принтер", "Драйвер", "Порт", "Сетевой", "По умолчанию", "Состояние"])
        for p in real:
            table.add(clean(p.get("Name")), clean(p.get("DriverName")), clean(p.get("PortName")),
                      fbool(p.get("Network")), "да" if p.get("Default") else "",
                      "автономно" if p.get("WorkOffline") else "")
    if virtual:
        sec.kv().add("Виртуальные принтеры", ", ".join(virtual))
    return sec


def build_optical(ctx):
    sec = Section("optical", "Оптические приводы")
    drives = ctx.rows("cdrom")
    if drives:
        table = sec.table(None, ["Привод", "Буква", "Производитель"])
        for d in drives:
            table.add(clean(d.get("Name")), clean(d.get("Drive")), clean(d.get("Manufacturer")))
    return sec


def build_tpm(ctx):
    sec = Section("tpm", "Модуль TPM")
    tpm = ctx.first("tpm")
    if tpm:
        kv = sec.kv()
        spec = clean(tpm.get("SpecVersion"))
        version = spec.split(",")[0].strip() if spec else None
        kv.add("Версия TPM", version)
        kv.add("Производитель", clean(tpm.get("ManufacturerIdTxt")))
        kv.add("Версия прошивки", clean(tpm.get("ManufacturerVersion")))
        kv.add("Включён", fbool(tpm.get("IsEnabled_InitialValue")))
        kv.add("Активирован", fbool(tpm.get("IsActivated_InitialValue")))
        kv.add("Есть владелец", fbool(tpm.get("IsOwned_InitialValue")))
        kv.add("Спецификация", spec)
        if version:
            ctx.facts["TPM"] = f"версия {version}"
        return sec
    found = [clean(d.get("Name")) for d in ctx.pnp()
             if re.search(r"TPM|Trusted Platform|доверенн", str(d.get("Name") or ""), re.I)]
    if found:
        sec.kv().add("Обнаружено устройство", ", ".join(x for x in found if x))
        ctx.facts["TPM"] = ", ".join(x for x in found if x)
    if ctx.errors.get("tpm"):
        sec.notes.append("Подробные сведения о TPM доступны только при запуске от имени администратора.")
    elif not found and ctx.rows("pnp"):
        sec.notes.append("TPM не обнаружен или отключён в BIOS/UEFI.")
    return sec


def build_problems(ctx):
    sec = Section("problems", "Устройства с неполадками")
    bad = [d for d in ctx.pnp()
           if to_int(d.get("ConfigManagerErrorCode")) not in (0, None, 45) or has_no_driver(ctx, d)]
    if bad:
        table = sec.table(None, ["Устройство", "Класс", "Проблема", "Что это", "ID устройства"],
                          masked=["ID устройства"])
        harmless = 0
        for d in sorted(bad, key=lambda x: str(x.get("Name"))):
            cls = d.get("PNPClass")
            hint, service = device_hint(d)
            if service and to_int(d.get("ConfigManagerErrorCode")) in (0, None, 28):
                harmless += 1
            table.add(clean(d.get("Name")) or "Неизвестное устройство", PNP_CLASSES.get(cls, cls) or "",
                      pnp_status(ctx, d), hint, d.get("PNPDeviceID"))
        fact = str(len(bad))
        if harmless == len(bad):
            fact += " (все — служебные каналы Bluetooth, драйвер им не нужен)"
            sec.notes.append("Это служебные каналы сопряжённых Bluetooth-устройств (наушников, телефона) "
                             "для их фирменных приложений. На работу компьютера и звук они не влияют. "
                             "Исчезнут, если удалить эти устройства в параметрах Bluetooth.")
        elif harmless:
            fact += f" (из них {harmless} — служебные каналы Bluetooth, драйвер им не нужен)"
        ctx.facts["Устройства с неполадками"] = fact

    real = len(bad) - (harmless if bad else 0)
    items = []
    if real:
        items.append((1, f"{real} {ru_plural(real, ('устройство', 'устройства', 'устройств'))} с неполадками — "
                         "см. раздел «Устройства с неполадками»"))
    elif ctx.rows("pnp"):
        items.append((0, "неисправных устройств нет"))
    no_driver = [d for d in ctx.pnp() if d.get("Status") == "нет драйвера"]
    if no_driver and ctx.platform == "linux":
        names = ", ".join(sorted({clean(d.get("Name")) or "?" for d in no_driver}))
        items.append((0, f"без драйвера Linux: {names} — обычно это не неисправность, "
                         "просто для этих устройств в системе нет драйвера"))
    if items:
        ctx.checks.append(("Устройства", verdict(items)))
    return sec


def build_checks(ctx):
    sec = Section("checks", "Проверка состояния")
    kv = sec.kv()
    for label, text in ctx.checks:
        kv.add(label, text)
    if ctx.dates:
        latest = max(ctx.dates, key=lambda d: (d[2], d[3]))
        text = "ℹ " + "; ".join(f"{name} — {made}" for name, made, _, _ in ctx.dates)
        if len(ctx.dates) > 1:
            text += f". Значит, компьютер собран не раньше, чем {latest[1]} (самая поздняя дата)"
        kv.add("Даты изготовления", text)
    if kv.rows:
        sec.notes.append("✔ — в порядке, ⚠ — обратите внимание, ✖ — неисправность. У нового компьютера износ "
                         "батареи 0–5 %, наработка диска — не больше нескольких десятков часов и никаких ошибок "
                         "SMART. Пороги ориентировочные.")
    return sec


def build_devices(ctx):
    devices = ctx.pnp()
    sec = Section("devices", f"Все устройства ({len(devices)})")
    groups = {}
    for d in devices:
        cls = d.get("PNPClass") or ""
        groups.setdefault(PNP_CLASSES.get(cls, cls) or "Другие устройства", []).append(d)
    for title in sorted(groups, key=lambda t: (t == "Другие устройства", t.casefold())):
        items = groups[title]
        other = title == "Другие устройства"
        columns = ["Устройство", "Производитель", "Драйвер", "Состояние"]
        table = sec.table(f"{title} ({len(items)})", columns + (["Что это", "ID устройства"] if other else []),
                          collapsible=True, masked=["ID устройства"])
        for d in sorted(items, key=lambda x: str(x.get("Name"))):
            cells = [clean(d.get("Name")) or "Неизвестное устройство", clean(d.get("Manufacturer")),
                     ctx.driver_text(d.get("PNPDeviceID")), pnp_status(ctx, d)]
            if other:
                cells += [device_hint(d)[0], d.get("PNPDeviceID")]
            table.add(*cells)
    return sec


QUERY_NAMES = {
    "system": "сведения о компьютере", "product": "сведения о модели", "enclosure": "корпус",
    "os": "операционная система", "bios": "BIOS", "baseboard": "материнская плата", "cpu": "процессор",
    "memory": "модули памяти", "memarray": "слоты памяти", "gpu": "видеокарты", "monitor_id": "мониторы",
    "monitor_params": "размеры мониторов", "monitor_conn": "подключение мониторов",
    "physdisk": "накопители", "diskdrive": "накопители (Win32_DiskDrive)", "partition": "разделы",
    "logicaldisk": "логические диски", "netadapter": "сетевые адаптеры", "netconfig": "сетевые настройки",
    "sound": "звуковые устройства", "keyboard": "клавиатуры", "mouse": "мыши", "usbctrl": "контроллеры USB",
    "battery": "батарея", "battery_static": "паспортные данные батареи", "battery_full": "ёмкость батареи",
    "battery_cycles": "циклы заряда батареи", "printer": "принтеры", "cdrom": "оптические приводы",
    "tpm": "TPM", "pnp": "список устройств", "drivers": "драйверы",
    "disk_health": "SMART-показатели накопителей", "smbios": "таблицы прошивки SMBIOS", "smart": "SMART",
    "pci_ids": "названия PCI-устройств", "pci": "PCI-устройства", "usb": "USB-устройства", "usb_ids": "названия USB-устройств",
    "gpu": "видеокарты", "user": "имя пользователя",
}
LOCAL_NAMES = {
    "firmware": "режим загрузки", "secure_boot": "Secure Boot", "display_version": "выпуск Windows",
    "ubr": "номер обновления Windows", "gpu_registry": "видеопамять из реестра", "edid": "EDID мониторов",
    "displays": "режимы мониторов", "battery_report": "отчёт о батарее (powercfg)",
    "nvme_health": "журнал SMART NVMe-дисков",
    "battery_ioctl": "сведения о батарее от драйвера",
}


def build_notes(ctx, raw):
    sec = Section("notes", "Примечания")
    admin = ctx.local.get("is_admin")
    if admin is False and ctx.platform == "linux":
        sec.notes.append("Программа запущена без прав root, поэтому не показаны модули памяти, серийные номера "
                         "и SMART-показатели накопителей. Для полного отчёта запустите её так: "
                         "python3 hardware_info.py --elevate (или через sudo).")
    elif admin is False:
        sec.notes.append("Программа запущена без прав администратора, поэтому не показаны подробности TPM, "
                         "температура, износ и наработка накопителей. Для полного отчёта запустите её "
                         "с параметром --elevate или «от имени администратора».")
    has_battery = bool(ctx.rows("battery"))
    for key, message in ctx.errors.items():
        if key.startswith("battery_") and (not has_battery or ctx.battery_complete or ctx.battery_noted):
            continue
        if key in ("tpm", "disk_health") and admin is False:
            continue
        if key == "physdisk" and ctx.rows("diskdrive"):
            continue
        sec.notes.append(f"Не удалось получить данные «{QUERY_NAMES.get(key, key)}»: {str(message).strip()}")
    for key, message in (ctx.local.get("errors") or {}).items():
        if key in ("battery_report", "battery_ioctl") and ctx.battery_complete:
            continue
        sec.notes.append(f"Ошибка при чтении «{LOCAL_NAMES.get(key, key)}»: {message}")
    info = [f"данные собраны {fdatetime(ctx.collected_at)}"]
    if raw.get("duration"):
        info.append(f"за {fnum(raw['duration'], 1)} с")
    if (raw.get("wmi") or {}).get("ps_version"):
        info.append(f"PowerShell {raw['wmi']['ps_version']}")
    if raw.get("python"):
        info.append(f"Python {raw['python']}")
    sec.notes.append(f"hardware_info.py {VERSION}: " + ", ".join(info) + ".")
    return sec


def build_report(raw, include_devices=True):
    ctx = Ctx(raw)
    sections = [
        build_system(ctx), build_os(ctx), build_bios(ctx), build_baseboard(ctx), build_cpu(ctx),
        build_memory(ctx), build_gpu(ctx), build_monitors(ctx), build_storage(ctx), build_network(ctx),
        build_audio(ctx), build_input(ctx),
        build_pnp_class(ctx, "camera", "Камеры", ("Camera", "Image"), fact="Камера"),
        build_pnp_class(ctx, "bluetooth", "Bluetooth", ("Bluetooth",)),
        build_usb(ctx), build_battery(ctx), build_printers(ctx), build_optical(ctx), build_tpm(ctx),
        build_problems(ctx),
    ]
    if include_devices:
        sections.append(build_devices(ctx))
    sections.append(build_notes(ctx, raw))

    summary = Section("summary", "Сводка")
    kv = summary.kv()
    order = ["Компьютер", "Операционная система", "Процессор", "Материнская плата", "Оперативная память",
             "Видеокарта", "Видеокарты", "Монитор", "Мониторы", "Накопители", "Сеть", "Звук", "Камера",
             "Батарея", "BIOS", "TPM", "Устройства с неполадками"]
    for key in order:
        if key in ctx.facts:
            kv.add(key, ctx.facts[key])

    computer = clean(ctx.first("system").get("Name")) or os.environ.get("COMPUTERNAME") or "компьютер"
    report = Report(computer, fdatetime(ctx.collected_at))
    report.sections = [s for s in [summary, build_checks(ctx)] + sections if not s.is_empty()]
    return report


# ---------------------------------------------------------------------------
# Вывод: текст, HTML, JSON
# ---------------------------------------------------------------------------

def _cut(text, width):
    return text if len(text) <= width else text[:width - 1] + "…"


TEXT_COLUMN_LIMITS = {"Что это": 100}


def render_text(report, width=80):
    out = ["=" * width, report.title.upper().center(width).rstrip(),
           f"Компьютер: {report.computer}    Дата: {report.generated}".center(width).rstrip(), "=" * width]
    for sec in report.sections:
        out += ["", f"=== {sec.title.upper()} " + "=" * max(3, width - len(sec.title) - 5)]
        for block in sec.blocks:
            if not block.rows:
                continue
            if block.title:
                out += ["", f"  --- {block.title} ---"]
            if block.kind == "kv":
                label_w = max(len(r[0]) for r in block.rows) + 1
                out += [f"  {(r[0] + ':').ljust(label_w)}  {r[1]}" for r in block.rows]
            else:
                cols = [i for i, _ in enumerate(block.columns) if any(row[i] for row in block.rows)]
                widths = [min(TEXT_COLUMN_LIMITS.get(block.columns[i], 60),
                              max(len(block.columns[i]), *(len(row[i]) for row in block.rows))) for i in cols]

                def line(cells):
                    parts = [cells[i] if n == len(cols) - 1 else _cut(cells[i], w).ljust(w)
                             for n, (i, w) in enumerate(zip(cols, widths))]
                    return ("  " + "  ".join(parts)).rstrip()

                out += [line(block.columns), "  " + "  ".join("-" * w for w in widths)]
                out += [line(row) for row in block.rows]
        for note in sec.notes:
            out.append(f"  * {note}")
    out.append("")
    return "\n".join(out)


HTML_CSS = """
:root { --bg:#f5f6f8; --card:#ffffff; --text:#1c2230; --muted:#5f6b7a; --line:#e3e6eb;
        --accent:#2563eb; --chip:#eef2f8; --warn:#9a5b00; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#101318; --card:#181c23; --text:#e5e8ec; --muted:#9aa3af; --line:#2a303a;
          --accent:#7aa5ff; --chip:#222834; --warn:#e0a24a; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font:15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
.wrap { max-width:1120px; margin:0 auto; padding:28px 16px 56px; }
header h1 { margin:0 0 4px; font-size:26px; font-weight:650; }
header .meta { color:var(--muted); font-size:14px; }
nav { display:flex; flex-wrap:wrap; gap:6px; margin:18px 0 6px; }
nav a { font-size:13px; padding:3px 11px; border-radius:999px; background:var(--chip);
        color:var(--text); text-decoration:none; border:1px solid var(--line); }
nav a:hover { border-color:var(--accent); color:var(--accent); }
section { background:var(--card); border:1px solid var(--line); border-radius:12px;
          padding:18px 22px; margin:16px 0; }
section h2 { margin:0 0 10px; font-size:19px; font-weight:650; }
section#summary { border-left:4px solid var(--accent); }
h3 { margin:18px 0 6px; font-size:14px; font-weight:600; color:var(--muted); }
table { border-collapse:collapse; width:100%; font-size:14px; }
.kv th { width:34%; text-align:left; font-weight:400; color:var(--muted);
         padding:4px 14px 4px 0; vertical-align:top; }
.kv td { padding:4px 0; overflow-wrap:anywhere; }
.scroll { overflow-x:auto; }
.data th { text-align:left; font-size:13px; font-weight:600; color:var(--muted);
           border-bottom:1px solid var(--line); padding:6px 14px 6px 0; white-space:nowrap; }
.data td { border-bottom:1px solid var(--line); padding:5px 14px 5px 0; vertical-align:top; }
.data tr:last-child td { border-bottom:none; }
.data td.id { font-family:Consolas, "Cascadia Mono", monospace; font-size:12.5px; word-break:break-all; min-width:220px; }
details { border-top:1px solid var(--line); }
details:last-of-type { border-bottom:1px solid var(--line); }
summary { cursor:pointer; padding:8px 0; font-weight:600; font-size:14px; }
.notes { margin:10px 0 0; padding-left:18px; color:var(--muted); font-size:13.5px; }
.bad { color:var(--warn); font-weight:600; }
footer { color:var(--muted); font-size:12.5px; text-align:center; margin-top:28px; }
@media (max-width:640px) { .kv th { width:45%; } section { padding:14px; } }
@media print { nav { display:none; } section { break-inside:avoid; border-color:#ccc; }
               details { display:block; } }
"""

OK_STATES = {"", "работает"}


def render_html(report):
    e = html.escape
    out = ["<!DOCTYPE html>", '<html lang="ru"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>Оборудование — {e(report.computer)}</title>", f"<style>{HTML_CSS}</style></head><body>",
           '<div class="wrap"><header>', f"<h1>{e(report.title)}</h1>",
           f'<div class="meta">Компьютер: <b>{e(report.computer)}</b> · отчёт от {e(report.generated or "")}</div>',
           "</header><nav>"]
    out += [f'<a href="#{s.id}">{e(s.title)}</a>' for s in report.sections]
    out.append("</nav>")
    for sec in report.sections:
        out.append(f'<section id="{sec.id}"><h2>{e(sec.title)}</h2>')
        for block in sec.blocks:
            if not block.rows:
                continue
            if block.kind == "kv":
                if block.title:
                    out.append(f"<h3>{e(block.title)}</h3>")
                out.append('<table class="kv">')
                for r in block.rows:
                    cls = ' class="bad"' if r[1][:1] in ("⚠", "✖") else ""  # замечания проверки
                    out.append(f"<tr><th>{e(r[0])}</th><td{cls}>{e(r[1])}</td></tr>")
                out.append("</table>")
                continue
            cols = [i for i, _ in enumerate(block.columns) if any(row[i] for row in block.rows)]
            status_col = next((block.columns.index(c) for c in ("Состояние", "Проблема") if c in block.columns), None)
            id_col = block.columns.index("ID устройства") if "ID устройства" in block.columns else None
            body = ['<div class="scroll"><table class="data"><tr>']
            body += [f"<th>{e(block.columns[i])}</th>" for i in cols]
            body.append("</tr>")
            for row in block.rows:
                cells = []
                for i in cols:
                    cls = ' class="bad"' if i == status_col and row[i] not in OK_STATES else ""
                    cls = ' class="id"' if i == id_col else cls
                    cells.append(f"<td{cls}>{e(row[i])}</td>")
                body.append("<tr>" + "".join(cells) + "</tr>")
            body.append("</table></div>")
            if block.collapsible:
                out.append(f"<details><summary>{e(block.title or '')}</summary>")
                out += body
                out.append("</details>")
            else:
                if block.title:
                    out.append(f"<h3>{e(block.title)}</h3>")
                out += body
        if sec.notes:
            out.append('<ul class="notes">' + "".join(f"<li>{e(n)}</li>" for n in sec.notes) + "</ul>")
        out.append("</section>")
    out.append(f"<footer>Создано программой hardware_info.py {VERSION}</footer></div></body></html>")
    return "\n".join(out)


def render_json(report):
    sections = []
    for sec in report.sections:
        blocks = []
        for b in sec.blocks:
            if b.kind == "kv":
                blocks.append({"type": "kv", "title": b.title,
                               "rows": [{"label": r[0], "value": r[1]} for r in b.rows]})
            else:
                blocks.append({"type": "table", "title": b.title, "columns": b.columns, "rows": b.rows})
        sections.append({"id": sec.id, "title": sec.title, "blocks": blocks, "notes": sec.notes})
    return {"title": report.title, "computer": report.computer, "generated": report.generated,
            "generator": f"hardware_info.py {VERSION}", "sections": sections}


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------

def relaunch_as_admin(argv, out_dir):
    params = [] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)]
    params += [a for a in argv if a != "--elevate"] + ["--output", out_dir]
    if "--pause" not in params:
        params.append("--pause")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                             subprocess.list2cmdline(params), out_dir, 1)
    return rc > 32


def safe_name(text):
    return re.sub(r"[^\w\-]+", "_", text, flags=re.UNICODE).strip("_") or "pc"


def give_to_sudo_user(path):
    """При запуске через sudo отдать файл обычному пользователю, чтобы он мог его открыть и удалить."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if IS_LINUX and os.geteuid() == 0 and uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except (OSError, ValueError):
            pass


def open_report(path):
    if IS_WINDOWS:
        os.startfile(path)
        return
    cmd = ["xdg-open", path]
    uid, user = os.environ.get("SUDO_UID"), os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and uid and user:  # браузер нужно открыть от имени пользователя, а не root
        env = [f"XDG_RUNTIME_DIR=/run/user/{uid}", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"]
        env += [f"{k}={os.environ[k]}" for k in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY") if os.environ.get(k)]
        cmd = ["sudo", "-u", user, "env"] + env + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        print(f"Не удалось открыть отчёт автоматически, откройте его вручную: {path}", file=sys.stderr)


def save_reports(report, formats, out_dir, stamp, anon):
    base = f"hardware_{'report' if anon else safe_name(report.computer)}_{stamp}"
    renderers = {
        "txt": (lambda: render_text(report), "utf-8-sig"),
        "html": (lambda: render_html(report), "utf-8"),
        "json": (lambda: json.dumps(render_json(report), ensure_ascii=False, indent=2), "utf-8"),
    }
    saved = []
    for fmt in formats:
        render, encoding = renderers[fmt]
        content = render()
        for folder in (out_dir, os.path.join(os.path.expanduser("~"), "Documents"), os.path.expanduser("~")):
            try:
                os.makedirs(folder, exist_ok=True)
                path = os.path.join(folder, f"{base}.{fmt}")
                with open(path, "w", encoding=encoding, newline="\r\n" if fmt == "txt" else "\n") as fh:
                    fh.write(content)
                give_to_sudo_user(path)
                saved.append(path)
                break
            except OSError as exc:
                print(f"Не удалось сохранить в {folder}: {exc}", file=sys.stderr)
    return saved


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="hardware_info.py",
        description="Собирает подробные сведения об оборудовании компьютера под Windows и Linux "
                    "и сохраняет отчёт в TXT, HTML и JSON.")
    parser.add_argument("-o", "--output", default=os.getcwd(),
                        help="папка для отчётов (по умолчанию — текущая)")
    parser.add_argument("-f", "--formats", nargs="+", choices=["txt", "html", "json"],
                        default=["txt", "html", "json"], help="форматы файлов отчёта (по умолчанию все)")
    parser.add_argument("--no-save", action="store_true", help="не сохранять файлы, только вывести в консоль")
    parser.add_argument("-q", "--quiet", action="store_true", help="не выводить отчёт в консоль")
    parser.add_argument("--anon", action="store_true",
                        help="скрыть серийные номера, UUID, MAC и IP-адреса, имена компьютера и пользователя")
    parser.add_argument("--no-devices", action="store_true", help="не включать полный список устройств")
    parser.add_argument("--open", action="store_true", help="открыть HTML-отчёт после создания")
    parser.add_argument("--elevate", action="store_true",
                        help="получить права администратора (в Linux — root через sudo): больше данных — "
                             "модули памяти, SMART, TPM и др.")
    parser.add_argument("--pause", action="store_true", help="ждать нажатия Enter перед выходом")
    parser.add_argument("--dump-raw", action="store_true", help="сохранить также «сырые» данные (для отладки)")
    parser.add_argument("--load-raw", metavar="FILE", help="построить отчёт из ранее сохранённых сырых данных")
    parser.add_argument("--collect-to", metavar="FILE", help=argparse.SUPPRESS)  # служебный: сбор под sudo
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def run(args, argv):
    if args.load_raw:
        with open(args.load_raw, encoding="utf-8") as fh:
            raw = json.load(fh)
    elif IS_LINUX:
        if args.elevate and os.geteuid() != 0 and not args.collect_to:
            raw = collect_linux_elevated()
        else:
            print("Собираю сведения об оборудовании…", file=sys.stderr)
            raw = collect_linux()
        if args.collect_to:  # служебный режим: отдать сырые данные запустившему процессу
            text = json.dumps(raw)
            if args.collect_to == "-":
                sys.stdout.write(text)
            else:
                with open(args.collect_to, "w", encoding="utf-8") as fh:
                    fh.write(text)
            return 0
    else:
        if not IS_WINDOWS:
            print("Эта программа работает в Windows и Linux.", file=sys.stderr)
            return 1
        out_dir = os.path.abspath(args.output)
        if args.elevate and not is_admin():
            if relaunch_as_admin(argv, out_dir):
                print("Открыто новое окно с правами администратора — отчёт появится там.")
                return 0
            print("Не удалось получить права администратора, продолжаю с обычными правами.", file=sys.stderr)
        print("Собираю сведения об оборудовании, это займёт от 10 секунд до минуты…", file=sys.stderr)
        started = time.time()
        wmi = collect_wmi()
        wmi_data = wmi.get("data") or {}
        local = collect_local(has_battery=bool(wmi_data.get("battery")),
                              nvme_disks=[d.get("DeviceId") for d in as_list(wmi_data.get("physdisk"))
                                          if isinstance(d, dict) and to_int(d.get("BusType")) == 17])
        raw = {"collected_at": dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
               "duration": round(time.time() - started, 1), "python": sys.version.split()[0],
               "wmi": wmi, "local": local}

    report = build_report(raw, include_devices=not args.no_devices)
    if args.anon:
        anonymize(report)
    if not args.quiet:
        print(render_text(report))

    saved = []
    stamp = (parse_dt(raw.get("collected_at")) or dt.datetime.now()).strftime("%Y%m%d_%H%M%S")
    if not args.no_save:
        saved = save_reports(report, args.formats, os.path.abspath(args.output), stamp, args.anon)
        if args.dump_raw and not args.load_raw:
            path = os.path.join(os.path.abspath(args.output), f"hardware_raw_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(raw, fh, ensure_ascii=False, indent=1)
            give_to_sudo_user(path)
            saved.append(path)
            if args.anon:
                print("Внимание: файл с сырыми данными не обезличивается.", file=sys.stderr)
    if saved:
        print("Отчёт сохранён:")
        for path in saved:
            print(f"  {path}")
    if args.open and (IS_WINDOWS or IS_LINUX):
        html_files = [p for p in saved if p.endswith(".html")]
        if html_files:
            open_report(html_files[0])
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    try:
        code = run(args, argv)
    except CollectError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        code = 1
    except KeyboardInterrupt:
        code = 130
    except BrokenPipeError:  # вывод передан, например, в head и закрыт раньше времени
        code = 0
    if args.pause:
        try:
            input("\nНажмите Enter, чтобы закрыть окно…")
        except (EOFError, KeyboardInterrupt):
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
