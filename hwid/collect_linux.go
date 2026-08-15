//go:build linux

package hwid

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func readFileTrimmed(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// cpuSerial reads the ARM board serial from /proc/cpuinfo when present.
func cpuSerial() (string, bool) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, found := strings.Cut(line, ":"); found && strings.TrimSpace(key) == "Serial" {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// diskSerial reads the first block-device identity available through sysfs.
func diskSerial() (string, bool) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}
		for _, candidate := range []string{
			"/sys/block/" + name + "/device/ident",
			"/sys/block/" + name + "/device/serial",
			"/sys/block/" + name + "/serial",
		} {
			if serial, ok := readFileTrimmed(candidate); ok && serial != "" {
				return serial, true
			}
		}
	}
	return "", false
}

// macAddress returns the MAC of the first physical-looking NIC.
func macAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		if strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "tun") ||
			strings.HasPrefix(iface.Name, "tap") || strings.HasPrefix(iface.Name, "tailscale") ||
			strings.HasPrefix(iface.Name, "zt") || strings.HasPrefix(iface.Name, "wg") {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}

// Collect gathers the available hardware factors on Linux. machine_guid
// (/etc/machine-id) is required and fails closed; the rest degrade
// gracefully. SMBIOS values under /sys/class/dmi/id are root-readable only,
// so they simply drop out for unprivileged processes.
func Collect() (map[string]string, error) {
	factors := map[string]string{}

	machineID, ok := readFileTrimmed("/etc/machine-id")
	if !ok || machineID == "" {
		machineID, ok = readFileTrimmed("/var/lib/dbus/machine-id")
	}
	if !ok || machineID == "" {
		return nil, fmt.Errorf("hwid: /etc/machine-id unavailable")
	}
	factors["machine_guid"] = machineID

	if productUUID, ok := readFileTrimmed("/sys/class/dmi/id/product_uuid"); ok {
		factors["product_uuid"] = productUUID
	}
	if boardSerial, ok := readFileTrimmed("/sys/class/dmi/id/board_serial"); ok {
		factors["board_serial"] = boardSerial
	}
	if serial, ok := cpuSerial(); ok {
		factors["cpu_id"] = serial
	}
	if serial, ok := diskSerial(); ok {
		factors["disk_serial"] = serial
	}
	if mac := macAddress(); mac != "" {
		factors["mac"] = mac
	}
	return factors, nil
}

// DeviceHWID derives the HWID for this machine in one call.
func DeviceHWID() (string, error) {
	factors, err := Collect()
	if err != nil {
		return "", err
	}
	return Compose(factors), nil
}
