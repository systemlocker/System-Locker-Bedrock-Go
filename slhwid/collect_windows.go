// collect_windows.go gathers the §4A.1 factor slots on Windows. The legacy
// slots reuse the shared hwid collector; the extended slots come from the
// registry, environment, and best-effort wmic queries (a missing source just
// leaves the slot absent — the threshold scheme absorbs it).
//go:build windows

package slhwid

import (
	"os"
	"regexp"
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

// wmicColumn parses one wmic get column into its trimmed non-empty values.
func wmicColumn(entity, column string) []string {
	out, err := runCmd(8*time.Second, "wmic", entity, "get", column)
	if err != nil {
		return nil
	}
	var values []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, column) {
			continue
		}
		values = append(values, line)
	}
	return values
}

// volumeSerial extracts the system drive's volume serial ("xxxx-xxxx"),
// matching on the hex pattern so localized `vol` output still works.
func volumeSerial() string {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	out, err := runCmd(5*time.Second, "cmd", "/c", "vol", drive)
	if err != nil {
		return ""
	}
	matches := regexp.MustCompile(`([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})`).FindAllString(out, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
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

	if serials := wmicColumn("diskdrive", "SerialNumber"); len(serials) > 0 {
		if v := multiInstance(serials); v != "" {
			factors["disk_serial"] = v
		}
	}

	if totals := wmicColumn("ComputerSystem", "TotalPhysicalMemory"); len(totals) > 0 {
		digits := regexp.MustCompile(`\d+`).FindString(totals[0])
		if digits != "" {
			factors["ram_total"] = digits
		}
	}

	if v := volumeSerial(); v != "" {
		factors["volume_id"] = v
	}

	return factors, nil
}
