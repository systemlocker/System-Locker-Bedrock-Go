// collect_linux.go gathers the §4A.1 factor slots on Linux: the legacy slots
// reuse the shared hwid collector (sysfs, /etc/machine-id) and the extended
// slots come from procfs, os-release, findmnt, and DRM EDID files.
//go:build linux

package slhwid

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systemlocker/system-locker-bedrock-go/hwid"
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

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		if m := regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\n]+)"?`).FindStringSubmatch(string(data)); m != nil {
			factors["os_build"] = m[1]
		}
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
		sort.Strings(blobs)
		factors["monitor_edid"] = strings.Join(blobs, "|")
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
		sort.Strings(gpus)
		factors["gpu_id"] = strings.Join(gpus, "|")
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
