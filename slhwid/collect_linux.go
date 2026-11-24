// collect_linux.go gathers the SL-HWID factor slots on Linux: the legacy slots
// reuse the shared hwid collector (sysfs, /etc/machine-id) and the extended
// slots come from procfs, os-release, findmnt, and DRM EDID files.
//go:build linux

package slhwid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/systemlocker/system-locker-bedrock-go/v2/hwid"
)

func Collect() (map[string]string, error) {
	factors := map[string]string{}
	if base, err := hwid.Collect(); err == nil {
		for name, value := range base {
			factors[name] = value
		}
	}

	if host, err := os.Hostname(); err == nil && host != "" {
		factors["computer_name"] = host
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		if m := regexp.MustCompile(`MemTotal:\s+(\d+)\s+kB`).FindStringSubmatch(string(data)); m != nil {
			if kb, err := strconv.ParseUint(m[1], 10, 64); err == nil {
				factors["ram_total"] = strconv.FormatUint(kb*1024, 10)
			}
		}
	}

	if out, err := runCmd(2*time.Second, "findmnt", "-no", "UUID", "/"); err == nil {
		if v := strings.TrimSpace(out); v != "" {
			factors["volume_id"] = v
		}
	}

	if data, err := os.ReadFile("/sys/class/dmi/id/bios_version"); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			factors["firmware"] = v
		}
	}
	// Keep product_uuid for schema-v1 recovery and expose the documented raw
	// signal under its schema-v2 name as well.
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if value := strings.TrimSpace(string(data)); value != "" {
			factors["system_uuid"] = value
		}
	}
	for slot, path := range map[string]string{
		"system_serial":  "/sys/class/dmi/id/product_serial",
		"chassis_serial": "/sys/class/dmi/id/chassis_serial",
	} {
		if data, err := os.ReadFile(path); err == nil {
			if value := strings.TrimSpace(string(data)); value != "" {
				factors[slot] = value
			}
		}
	}
	if out, err := runCmd(4*time.Second, "dmidecode", "--type", "memory"); err == nil {
		if serials := allMatches(`(?m)^\s*Serial Number:\s*(\S.*)$`, out); len(serials) > 0 {
			factors["memory_modules"] = joinInstances(serials)
		}
	}
	var nicIDs []string
	ifaces, _ := filepath.Glob("/sys/class/net/*")
	for _, iface := range ifaces {
		if _, err := os.Stat(filepath.Join(iface, "device")); err != nil {
			continue // virtual interface
		}
		if data, err := os.ReadFile(filepath.Join(iface, "perm_address")); err == nil {
			if value := strings.TrimSpace(string(data)); value != "" && value != "00:00:00:00:00:00" {
				nicIDs = append(nicIDs, value)
			}
		}
	}
	if len(nicIDs) > 0 {
		factors["nic_identity"] = joinInstances(nicIDs)
	}
	var batteries []string
	batteryPaths, _ := filepath.Glob("/sys/class/power_supply/BAT*/serial_number")
	for _, path := range batteryPaths {
		if data, err := os.ReadFile(path); err == nil {
			if value := strings.TrimSpace(string(data)); value != "" {
				batteries = append(batteries, value)
			}
		}
	}
	if len(batteries) > 0 {
		factors["battery_serial"] = joinInstances(batteries)
	}
	for _, path := range []string{"/sys/class/tpm/tpm0/device/ek_pub", "/sys/class/tpm/tpm0/ek_pub"} {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			digest := sha256.Sum256(data)
			factors["tpm_ek"] = hex.EncodeToString(digest[:])
			break
		}
	}

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		if m := regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\n]+)"?`).FindStringSubmatch(string(data)); m != nil {
			factors["os_build"] = m[1]
		}
	}

	// fixed_disk_serial (schema v3): every block device with a serial that is
	// neither marked removable nor attached through USB. NVMe/SCSI expose
	// device/serial; virtio exposes serial on the block device itself.
	var fixedDisks []string
	blockDevices, _ := filepath.Glob("/sys/block/*")
	for _, block := range blockDevices {
		if data, err := os.ReadFile(filepath.Join(block, "removable")); err == nil && strings.TrimSpace(string(data)) == "1" {
			continue
		}
		if target, err := filepath.EvalSymlinks(block); err == nil && strings.Contains(target, "/usb") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(block, "device", "serial"))
		if err != nil {
			data, err = os.ReadFile(filepath.Join(block, "serial"))
		}
		if err == nil {
			fixedDisks = append(fixedDisks, string(data))
		}
	}
	if v := joinInstances(fixedDisks); v != "" {
		factors["fixed_disk_serial"] = v
	}

	// monitor_edid: hex of every non-empty DRM EDID blob, sorted.
	var blobs []string
	edids, _ := filepath.Glob("/sys/class/drm/card*-*/edid")
	for _, path := range edids {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		blobs = append(blobs, hexLower(data))
	}
	if len(blobs) > 0 {
		factors["monitor_edid"] = joinInstances(blobs)
	}

	// gpu_id: display-class PCI devices (class 0x03xxxx), vendor:device.
	pci, _ := filepath.Glob("/sys/bus/pci/devices/*/class")
	var gpus []string
	for _, classPath := range pci {
		data, err := os.ReadFile(classPath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(string(data)), "0x03") {
			continue
		}
		dir := filepath.Dir(classPath)
		vendor, err1 := os.ReadFile(filepath.Join(dir, "vendor"))
		device, err2 := os.ReadFile(filepath.Join(dir, "device"))
		if err1 == nil && err2 == nil {
			gpus = append(gpus, strings.TrimSpace(string(vendor))+":"+strings.TrimSpace(string(device)))
		}
	}
	if len(gpus) > 0 {
		factors["gpu_id"] = joinInstances(gpus)
	}

	return factors, nil
}

func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
