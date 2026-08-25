// collect_darwin.go gathers the §4A.1 factor slots on macOS through the
// system command-line tools, keeping the library dependency-free. Every
// source degrades gracefully; slow tools (system_profiler) run under a hard
// timeout and simply leave their slot absent when they miss it.
//go:build darwin

package slhwid

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func Collect() (map[string]string, error) {
	factors := map[string]string{}

	// IOPlatformUUID (machine_guid) and IOPlatformSerialNumber
	// (board_serial) come from one ioreg call.
	if out, err := runCmd(3*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		if v := firstMatch(`"IOPlatformUUID"\s*=\s*"([^"]+)"`, out); v != "" {
			factors["machine_guid"] = v
		}
		if v := firstMatch(`"IOPlatformSerialNumber"\s*=\s*"([^"]+)"`, out); v != "" {
			factors["board_serial"] = v
			factors["system_serial"] = v
		}
	}

	// cpu_id: brand string (Intel) or model (Apple Silicon) plus core count.
	brand := ""
	if out, err := runCmd(2*time.Second, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
		brand = strings.TrimSpace(out)
	}
	if brand == "" {
		if out, err := runCmd(2*time.Second, "sysctl", "-n", "hw.model"); err == nil {
			brand = strings.TrimSpace(out)
		}
	}
	if cores, err := runCmd(2*time.Second, "sysctl", "-n", "hw.physicalcpu"); err == nil {
		cores = strings.TrimSpace(cores)
		if brand != "" && cores != "" {
			factors["cpu_id"] = brand + "-" + cores
		}
	}

	if out, err := runCmd(2*time.Second, "ifconfig", "en0"); err == nil {
		if v := firstMatch(`ether\s+([0-9a-fA-F:]{17})`, out); v != "" {
			factors["mac"] = v
		}
	}
	if out, err := runCmd(3*time.Second, "networksetup", "-listallhardwareports"); err == nil {
		if addresses := allMatches(`(?i)Ethernet Address:\s*([0-9a-f:]{17})`, out); len(addresses) > 0 {
			sort.Strings(addresses)
			factors["nic_identity"] = strings.Join(addresses, "|")
		}
	}

	if out, err := runCmd(2*time.Second, "sysctl", "-n", "hw.memsize"); err == nil {
		factors["ram_total"] = strings.TrimSpace(out)
	}

	// volume_id: root volume UUID from diskutil's plist output.
	if out, err := runCmd(3*time.Second, "diskutil", "info", "-plist", "/"); err == nil {
		if v := firstMatch(`<key>VolumeUUID</key>\s*<string>([^<]+)</string>`, out); v != "" {
			factors["volume_id"] = v
		}
	}

	if out, err := runCmd(2*time.Second, "scutil", "--get", "ComputerName"); err == nil {
		if v := strings.TrimSpace(out); v != "" {
			factors["computer_name"] = v
		} else if out2, err2 := runCmd(2*time.Second, "scutil", "--get", "LocalHostName"); err2 == nil {
			if v := strings.TrimSpace(out2); v != "" {
				factors["computer_name"] = v
			}
		}
	}

	// firmware: boot ROM version from the hardware profile.
	if out, err := runCmd(5*time.Second, "system_profiler", "SPHardwareDataType", "-json"); err == nil {
		if v := firstMatch(`"spmachine_bootrom_version"\s*:\s*"([^"]+)"`, out); v != "" {
			factors["firmware"] = v
		}
	}
	if out, err := runCmd(5*time.Second, "system_profiler", "SPMemoryDataType", "-json"); err == nil {
		if serials := allMatches(`"[^"]*serial[^"]*"\s*:\s*"([^"]+)"`, out); len(serials) > 0 {
			sort.Strings(serials)
			factors["memory_modules"] = strings.Join(serials, "|")
		}
	}
	if out, err := runCmd(3*time.Second, "ioreg", "-r", "-c", "AppleSmartBattery"); err == nil {
		serial := firstMatch(`"BatterySerialNumber"\s*=\s*"([^"]+)"`, out)
		if serial == "" {
			serial = firstMatch(`"Serial"\s*=\s*"?([^"\n]+)"?`, out)
		}
		if serial != "" {
			factors["battery_serial"] = serial
		}
	}

	// gpu_id: every display model, sorted (§4A.1 multi-instance form).
	if out, err := runCmd(5*time.Second, "system_profiler", "SPDisplaysDataType", "-json"); err == nil {
		if models := allMatches(`"spdisplays_model"\s*:\s*"([^"]+)"`, out); len(models) > 0 {
			sort.Strings(models)
			factors["gpu_id"] = strings.Join(models, "|")
		}
	}

	// disk_serial: physical-disk serials from the storage profile (the key
	// name varies by transport, so any serial-ish key is accepted).
	if out, err := runCmd(5*time.Second, "system_profiler", "SPStorageDataType", "-json"); err == nil {
		if serials := allMatches(`"[a-z_]*serial[a-z_]*"\s*:\s*"([^"]+)"`, out); len(serials) > 0 {
			sort.Strings(serials)
			factors["disk_serial"] = strings.Join(serials, "|")
		}
	}

	// monitor_edid: EDID hex blobs from IOKit.
	if out, err := runCmd(3*time.Second, "ioreg", "-r", "-c", "IODisplayConnect"); err == nil {
		if blobs := allMatches(`"IODisplayEDID"\s*=\s*<?([0-9a-fA-F]+)>?`, out); len(blobs) > 0 {
			sort.Strings(blobs)
			factors["monitor_edid"] = strings.ToLower(strings.Join(blobs, "|"))
		}
	}

	var version, build string
	if out, err := runCmd(2*time.Second, "sw_vers", "-productVersion"); err == nil {
		version = strings.TrimSpace(out)
	}
	if out, err := runCmd(2*time.Second, "sw_vers", "-buildVersion"); err == nil {
		build = strings.TrimSpace(out)
	}
	if version != "" && build != "" {
		factors["os_build"] = version + "-" + build
	}

	if len(factors) == 0 {
		return nil, fmt.Errorf("slhwid: no hardware factors available on this machine")
	}
	return factors, nil
}
