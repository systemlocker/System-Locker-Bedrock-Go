// collect_windows.go gathers the §4A.1 factor slots on Windows. The legacy
// slots reuse the shared hwid collector; the extended slots come from the
// registry, environment, and best-effort CIM queries (a missing source just
// leaves the slot absent — the threshold scheme absorbs it).
//go:build windows

package slhwid

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systemlocker/system-locker-bedrock-go/hwid"
)

// displayClassGUID is the Windows device setup class for display adapters.
const displayClassGUID = `{4d36e968-e325-11ce-bfc1-08002be10318}`

// multiInstance joins per-instance values in sorted order with "|" — the
// canonical multi-instance factor form (§4A.1).
func multiInstance(values []string) string {
	cleaned := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			cleaned = append(cleaned, v)
		}
	}
	sort.Strings(cleaned)
	return strings.Join(cleaned, "|")
}

// regTypedValue reads one value of any common type, returning the value
// column as text (multi-string values arrive space-joined on one line).
func regTypedValue(path, name string) (string, bool) {
	out, err := runCmd(5*time.Second, "reg", "query", path, "/v", name, "/reg:64")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ":
				if strings.EqualFold(fields[i-1], name) {
					return strings.Join(fields[i+1:], " "), true
				}
			}
		}
	}
	return "", false
}

// regValuesRecursive collects every value column named name under a
// recursive query of path (used for per-instance GPU names and EDID blobs).
func regValuesRecursive(path, name string) []string {
	out, err := runCmd(10*time.Second, "reg", "query", path, "/s", "/v", name, "/reg:64")
	if err != nil {
		return nil
	}
	var values []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 1; i+1 < len(fields); i++ {
			if strings.EqualFold(fields[i-1], name) {
				switch fields[i] {
				case "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_MULTI_SZ":
					values = append(values, strings.Join(fields[i+1:], ""))
				}
			}
		}
	}
	return values
}

// cimFactors gathers the newer schema-v2 signals in one PowerShell process.
// It is enrichment only: native values are never replaced by CIM results.
func cimFactors() map[string]string {
	const script = "$ErrorActionPreference='SilentlyContinue';" +
		"function Emit($n,$v){$c=@($v|Where-Object{$_ -ne $null -and ([string]$_).Trim().Length -gt 0}|ForEach-Object{([string]$_).Trim()}|Sort-Object);if($c.Count -gt 0){Write-Output ($n+'='+($c -join '|'))}};" +
		"$p=Get-CimInstance Win32_ComputerSystemProduct;Emit 'system_uuid' $p.UUID;Emit 'system_serial' $p.IdentifyingNumber;" +
		"Emit 'chassis_serial' (Get-CimInstance Win32_SystemEnclosure).SerialNumber;" +
		"Emit 'disk_serial' (Get-CimInstance Win32_DiskDrive).SerialNumber;" +
		"Emit 'memory_modules' (Get-CimInstance Win32_PhysicalMemory).SerialNumber;" +
		"Emit 'nic_identity' (Get-CimInstance Win32_NetworkAdapter|Where-Object{$_.PhysicalAdapter}).PermanentAddress;" +
		"Emit 'battery_serial' (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).SerialNumber;" +
		"$ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256;if($ek.IsPresent){Emit 'tpm_ek' $ek.PublicKeyHash}"
	out, err := runCmd(12*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil
	}
	known := map[string]bool{
		"system_uuid": true, "system_serial": true, "chassis_serial": true,
		"disk_serial": true, "memory_modules": true, "nic_identity": true,
		"battery_serial": true, "tpm_ek": true,
	}
	factors := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && known[name] && strings.TrimSpace(value) != "" {
			factors[name] = value
		}
	}
	return factors
}

// Collect gathers the available §4A factor slots on Windows. Missing
// optional slots degrade gracefully; the legacy collector's fail-closed
// machine GUID simply leaves that slot absent for this module.
func Collect() (map[string]string, error) {
	factors := map[string]string{}
	if base, err := hwid.Collect(); err == nil {
		for name, value := range base {
			factors[name] = value
		}
	}

	// The legacy collector reads the first whitespace-delimited token from a
	// registry value. SL-HWID shares helpers with the C++ and .NET collectors,
	// so its factor values must preserve the complete value (for example, the
	// multi-word CPU Identifier) before normalizing it.
	for _, entry := range []struct {
		name string
		path string
		key  string
	}{
		{"machine_guid", `HKLM\SOFTWARE\Microsoft\Cryptography`, "MachineGuid"},
		{"product_uuid", `HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation`, "ComputerHardwareId"},
		{"board_serial", `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardSerialNumber"},
		{"cpu_id", `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "Identifier"},
	} {
		if value, ok := regTypedValue(entry.path, entry.key); ok {
			if entry.name == "product_uuid" {
				// Windows reports ComputerHardwareId with braces; the shared
				// C++/.NET format deliberately stores the UUID without them.
				value = strings.Trim(value, "{}")
			}
			factors[entry.name] = value
		}
	}
	if value := nativeSystemUUID(); value != "" {
		factors["system_uuid"] = value
	}

	if v := os.Getenv("COMPUTERNAME"); v != "" {
		factors["computer_name"] = v
	}

	var firmwareParts []string
	if v, ok := regTypedValue(`HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "SystemBiosVersion"); ok {
		firmwareParts = append(firmwareParts, v)
	}
	if v, ok := regTypedValue(`HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "BIOSVersion"); ok {
		firmwareParts = append(firmwareParts, v)
	}
	if v := multiInstance(firmwareParts); v != "" {
		factors["firmware"] = v
	}

	if build, ok := regTypedValue(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuildNumber"); ok {
		ubr := ""
		if v, ok := regTypedValue(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "UBR"); ok {
			if u, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(v), "0x"), 16, 32); err == nil {
				ubr = strconv.FormatUint(u, 10)
			}
		}
		if ubr != "" {
			factors["os_build"] = build + "-" + ubr
		}
	}

	if descs := regValuesRecursive(`HKLM\SYSTEM\CurrentControlSet\Control\Class\`+displayClassGUID, "DriverDesc"); len(descs) > 0 {
		if v := multiInstance(descs); v != "" {
			factors["gpu_id"] = v
		}
	}

	if blobs := regValuesRecursive(`HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY`, "EDID"); len(blobs) > 0 {
		lowered := make([]string, 0, len(blobs))
		for _, b := range blobs {
			lowered = append(lowered, strings.ToLower(b))
		}
		if v := multiInstance(lowered); v != "" {
			factors["monitor_edid"] = v
		}
	}

	// CIM only enriches native collection; a provider cannot change the
	// semantics of an already-collected slot.
	for name, value := range cimFactors() {
		if _, exists := factors[name]; !exists {
			factors[name] = value
		}
	}

	if v := nativeRamTotal(); v != "" {
		factors["ram_total"] = v
	}
	if v := nativeVolumeSerial(); v != "" {
		factors["volume_id"] = v
	}

	return factors, nil
}
