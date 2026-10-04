#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сведения об оборудовании компьютера (Windows 10/11).

Собирает подробную информацию обо всём установленном железе: система и корпус,
BIOS/UEFI, материнская плата, процессор, оперативная память (по модулям),
видеокарты, мониторы, накопители и разделы, сетевые и звуковые адаптеры,
устройства ввода, камеры, Bluetooth, USB, батарея, принтеры, оптические
приводы, TPM, а также полный список устройств из Диспетчера устройств
с версиями драйверов и отдельным списком неисправных устройств.

Сторонние библиотеки не нужны: данные берутся из WMI/CIM через встроенный
в Windows PowerShell, а также из реестра и WinAPI (через ctypes).

Примеры запуска:
    python hardware_info.py              отчёт в консоль + файлы TXT, HTML, JSON
    python hardware_info.py --open       то же и сразу открыть HTML-отчёт
    python hardware_info.py --elevate    перезапуск с правами администратора
    python hardware_info.py --anon       скрыть серийные номера, MAC, IP и т. п.
    python hardware_info.py --help       все параметры
"""

from __future__ import annotations

import argparse
import codecs
import ctypes
import datetime as dt
import html
import json
import math
import os
import re
import shutil
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

VERSION = "1.2"
IS_WINDOWS = sys.platform == "win32"
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
        return False
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
            raise RuntimeError(f"powercfg не создал отчёт (код {proc.returncode})" + (f": {message}" if message else ""))
        return parse_battery_report(data)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def collect_local(has_battery=False):
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
    if has_battery:
        steps["battery_report"] = battery_report
    for key, func in steps.items():
        try:
            info[key] = func()
        except Exception as exc:  # отдельная неудача не должна ломать весь отчёт
            info.setdefault("errors", {})[key] = str(exc)
    return info


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
             131: "Linux", 238: "защитный GPT"}

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
        self.facts = OrderedDict()
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

        if hypervisor:
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
        if cur_mhz and max_mhz and abs(cur_mhz - max_mhz) > 50:
            kv.add("Текущая частота", f"{fnum(cur_mhz / 1000, 2)} ГГц")
        kv.add("Кэш L2", fbytes(l2 * 1024) if l2 else None)
        kv.add("Кэш L3", fbytes(l3 * 1024) if l3 else None)
        kv.add("Сокет", clean(c.get("SocketDesignation")))
        kv.add("Архитектура", CPU_ARCH.get(to_int(c.get("Architecture"))))
        kv.add("Разрядность", f"{c.get('AddressWidth')} бит" if to_int(c.get("AddressWidth")) else None)
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
    kv.add("Доступно Windows", fbytes(visible_kb * 1024) if visible_kb else fbytes(cs.get("TotalPhysicalMemory")))
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
                                        "Производитель", "Партномер", "Серийный номер"],
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
                  clean(m.get("PartNumber")), clean(m.get("SerialNumber")))

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


def gpu_vram(gpu, registry):
    name = (clean(gpu.get("Name")) or "").casefold()
    pnp = (gpu.get("PNPDeviceID") or "").lower()
    candidates = [e for e in registry or [] if (e.get("name") or "").casefold() == name]
    if len(candidates) > 1 and pnp:
        candidates = [e for e in candidates if (e.get("matching_id") or "").lower() in pnp] or candidates
    for e in candidates:
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
        vram = gpu_vram(g, registry)
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
        kv.add("Видеопамять", vram)
        kv.add("Текущий режим", mode)
        kv.add("Драйвер", driver)
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
    letters_by_disk = {}
    disk_by_letter = {}
    for p in parts:
        letter = drive_letter(p.get("DriveLetter"))
        if letter:
            letters_by_disk.setdefault(str(p.get("DiskNumber")), []).append(f"{letter}:")
            disk_by_letter[f"{letter}:"] = str(p.get("DiskNumber"))

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
            if any(errors):
                kv.add("Неисправленные ошибки чтения / записи", f"{errors[0]} / {errors[1]}")
            kv.add("Тома", ", ".join(sorted(letters_by_disk.get(did, []))) or None)

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
        table = sec.table("Разделы", ["Диск", "Раздел", "Буква", "Назначение", "Размер"])
        for p in sorted(parts, key=lambda x: (to_int(x.get("DiskNumber")) or 0, to_int(x.get("PartitionNumber")) or 0)):
            purpose = GPT_TYPES.get(str(p.get("GptType") or "").lower()) or MBR_TYPES.get(to_int(p.get("MbrType")))
            flags = [x for x in ("системный" if p.get("IsSystem") and "EFI" not in (purpose or "") else None,
                                 "загрузочный" if p.get("IsBoot") else None) if x]
            if flags:
                purpose = f"{purpose or 'раздел'} ({', '.join(flags)})"
            letter = drive_letter(p.get("DriveLetter"))
            table.add(p.get("DiskNumber"), p.get("PartitionNumber"), f"{letter}:" if letter else "",
                      purpose, fbytes(p.get("Size")))

    volumes = ctx.rows("logicaldisk")
    if volumes:
        table = sec.table("Логические диски", ["Диск", "Метка", "Файловая система", "Объём", "Свободно",
                                               "Тип", "Физический диск"])
        for v in sorted(volumes, key=lambda x: str(x.get("DeviceID"))):
            size, free = to_int(v.get("Size")), to_int(v.get("FreeSpace"))
            free_text = fbytes(free) if free is not None else ""
            if size and free is not None:
                free_text += f" ({round(free * 100 / size)} %)"
            dev = str(v.get("DeviceID") or "")
            phys = disk_by_letter.get(dev.upper())
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
    reports = [r for r in as_list(ctx.local.get("battery_report")) if isinstance(r, dict)]
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
                sec.notes.append("Прошивка не сообщает Windows паспортную ёмкость батареи (её нет даже в отчёте "
                                 "powercfg), поэтому износ посчитать нельзя. Паспортная ёмкость указана на "
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
        kv.add("Паспортная ёмкость", f"{fint(designed)} мВт·ч" if designed else None)
        kv.add("Полная ёмкость сейчас", f"{fint(current)} мВт·ч" if current else None)
        if wear is not None:
            kv.add("Износ", f"{fnum(wear, 1)} % (осталось {fnum(100 - wear, 1)} % паспортной ёмкости)")
        kv.add("Циклов заряда", cycle_count or None)
        kv.add("Серийный номер", clean(s.get("SerialNumber")) or clean(r.get("serial")), sensitive=True)
        parts = [x for x in (f"заряд {charge} %" if charge is not None else None,
                             f"износ {fnum(wear, 1)} %" if wear is not None else None) if x]
        if parts:
            summary.append(", ".join(parts))
    if count and not ctx.battery_complete and "battery_report" in ctx.local and not reports:
        sec.notes.append("В отчёте powercfg нет сведений о батарее, поэтому износ посчитать нельзя.")
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
    "disk_health": "SMART-показатели накопителей",
}
LOCAL_NAMES = {
    "firmware": "режим загрузки", "secure_boot": "Secure Boot", "display_version": "выпуск Windows",
    "ubr": "номер обновления Windows", "gpu_registry": "видеопамять из реестра", "edid": "EDID мониторов",
    "displays": "режимы мониторов", "battery_report": "отчёт о батарее (powercfg)",
}


def build_notes(ctx, raw):
    sec = Section("notes", "Примечания")
    admin = ctx.local.get("is_admin")
    if admin is False:
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
        if key == "battery_report" and ctx.battery_complete:
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
    report.sections = [s for s in [summary] + sections if not s.is_empty()]
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
                out += [f"<tr><th>{e(r[0])}</th><td>{e(r[1])}</td></tr>" for r in block.rows]
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
                saved.append(path)
                break
            except OSError as exc:
                print(f"Не удалось сохранить в {folder}: {exc}", file=sys.stderr)
    return saved


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="hardware_info.py",
        description="Собирает подробные сведения об оборудовании компьютера под Windows "
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
                        help="перезапуститься с правами администратора (больше данных: TPM, SMART и др.)")
    parser.add_argument("--pause", action="store_true", help="ждать нажатия Enter перед выходом")
    parser.add_argument("--dump-raw", action="store_true", help="сохранить также «сырые» данные (для отладки)")
    parser.add_argument("--load-raw", metavar="FILE", help="построить отчёт из ранее сохранённых сырых данных")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def run(args, argv):
    if args.load_raw:
        with open(args.load_raw, encoding="utf-8") as fh:
            raw = json.load(fh)
    else:
        if not IS_WINDOWS:
            print("Эта программа предназначена для Windows.", file=sys.stderr)
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
        local = collect_local(has_battery=bool((wmi.get("data") or {}).get("battery")))
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
            saved.append(path)
            if args.anon:
                print("Внимание: файл с сырыми данными не обезличивается.", file=sys.stderr)
    if saved:
        print("Отчёт сохранён:")
        for path in saved:
            print(f"  {path}")
    if args.open and IS_WINDOWS:
        html_files = [p for p in saved if p.endswith(".html")]
        if html_files:
            os.startfile(html_files[0])
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
    if args.pause:
        try:
            input("\nНажмите Enter, чтобы закрыть окно…")
        except (EOFError, KeyboardInterrupt):
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
