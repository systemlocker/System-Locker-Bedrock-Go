//go:build windows

package slhwid

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	getSystemFirmwareTable = kernel32.NewProc("GetSystemFirmwareTable")
	getVolumeInformation   = kernel32.NewProc("GetVolumeInformationW")
	globalMemoryStatusEx   = kernel32.NewProc("GlobalMemoryStatusEx")
)

func nativeSystemUUID() string {
	const rsmb = uint32('R') | uint32('S')<<8 | uint32('M')<<16 | uint32('B')<<24
	size, _, _ := getSystemFirmwareTable.Call(uintptr(rsmb), 0, 0, 0)
	if size < 8 || size > 1024*1024 {
		return ""
	}
	data := make([]byte, size)
	got, _, _ := getSystemFirmwareTable.Call(uintptr(rsmb), 0, uintptr(unsafe.Pointer(&data[0])), size)
	if got != size {
		return ""
	}
	table := data[8:]
	for offset := 0; offset+4 <= len(table); {
		kind, length := table[offset], int(table[offset+1])
		if length < 4 || offset+length > len(table) {
			return ""
		}
		if kind == 1 && length >= 24 {
			raw := table[offset+8 : offset+24]
			allZero, allFF := true, true
			for _, value := range raw {
				allZero = allZero && value == 0
				allFF = allFF && value == 0xff
			}
			if allZero || allFF {
				return ""
			}
			return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
		}
		offset += length
		for offset+1 < len(table) && (table[offset] != 0 || table[offset+1] != 0) {
			offset++
		}
		offset += 2
	}
	return ""
}

func nativeVolumeSerial() string {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	path, err := syscall.UTF16PtrFromString(drive + "\\")
	if err != nil {
		return ""
	}
	var serial uint32
	ok, _, _ := getVolumeInformation.Call(uintptr(unsafe.Pointer(path)), 0, 0, uintptr(unsafe.Pointer(&serial)), 0, 0, 0, 0)
	if ok == 0 {
		return ""
	}
	return fmt.Sprintf("%04X-%04X", serial>>16, serial&0xffff)
}

type memoryStatusEx struct {
	Length, Load                                                                                         uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
}

func nativeRamTotal() string {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	ok, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ok == 0 {
		return ""
	}
	return fmt.Sprint(status.TotalPhys)
}
