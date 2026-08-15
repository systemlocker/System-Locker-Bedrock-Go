//go:build !windows && !linux

package hwid

import "fmt"

// Collect on unsupported platforms returns an error: the shared
// specification only targets Windows and Linux for v1. Supply your own HWID
// through the client configuration instead.
func Collect() (map[string]string, error) {
	return nil, fmt.Errorf("hwid: hardware factor collection is not supported on this platform")
}

// DeviceHWID derives the HWID for this machine in one call.
func DeviceHWID() (string, error) {
	factors, err := Collect()
	if err != nil {
		return "", err
	}
	return Compose(factors), nil
}
