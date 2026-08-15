//go:build windows

package hwid

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// regValue reads one string value from the Windows registry through reg.exe,
// keeping the library dependency-free.
func regValue(path, name string) (string, error) {
	output, err := exec.Command("reg", "query", path, "/v", name).Output()
	if err != nil {
		return "", fmt.Errorf("registry query failed: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 1; i < len(fields)-1; i++ {
			if strings.EqualFold(fields[i], "REG_SZ") {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("registry value %s not found", name)
}

// macAddress returns the MAC of the first physical-looking NIC, or "" when
// none is identifiable.
func macAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		if isVirtualInterfaceName(iface.Name) {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{
		"vethernet", "vmware", "virtual", "loopback", "tap", "tun",
		"zerotier", "wsl", "docker", "bluetooth", "tailscale", "vpn",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// Collect gathers the available hardware factors on Windows. machine_guid
// is required and fails closed; the rest degrade gracefully.
//
// disk_serial is not collected on Windows in v1 (no fast dependency-free
// source); the remaining factors still produce a strong composite.
func Collect() (map[string]string, error) {
	factors := map[string]string{}

	machineGUID, err := regValue(`HKLM\SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
	if err != nil {
		return nil, fmt.Errorf("hwid: machine GUID unavailable: %w", err)
	}
	factors["machine_guid"] = machineGUID

	if hardwareID, err := regValue(`HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation`, "ComputerHardwareId"); err == nil {
		factors["product_uuid"] = strings.Trim(hardwareID, "{}")
	}
	if boardSerial, err := regValue(`HKLM\HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardSerialNumber"); err == nil {
		factors["board_serial"] = boardSerial
	}
	if cpuID, err := regValue(`HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "Identifier"); err == nil {
		factors["cpu_id"] = cpuID
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
