// collect_other.go fails closed on unsupported platforms: the module needs
// real hardware factors, and a software-only fallback would weaken it.
//go:build !windows && !linux && !darwin

package slhwid

import "fmt"

func Collect() (map[string]string, error) {
	return nil, fmt.Errorf("slhwid: secret-sharing HWID is not supported on this platform")
}
