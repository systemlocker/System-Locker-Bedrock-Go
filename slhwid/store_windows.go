// store_windows.go persists the module's secrets through reg.exe (keeping
// the library dependency-free), reading HKLM first and falling back to HKCU
// when the HKLM write is denied.
//go:build windows

package slhwid

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

const (
	regRootHKLM = `HKLM\SOFTWARE\SystemLocker`
	regRootHKCU = `HKCU\SOFTWARE\SystemLocker`
	slstoreName = "SLStore"
)

type registryStore struct{}

func (s *registryStore) lock() (func(), error) {
	directory, err := localLockDirectory()
	if err != nil {
		return nil, fmt.Errorf("slhwid: storage lock directory unavailable: %w", err)
	}
	return acquireStorageLock(directory)
}

func defaultStore(override string) (store, error) {
	if override != "" {
		return newDirStore(override)
	}
	return &registryStore{}, nil
}

// regReadBinary reads a REG_BINARY value from one root. reg.exe prints the
// bytes as one contiguous hex string (sometimes wrapped across continuation
// lines), so the parser joins every hex token after REG_BINARY and decodes
// the result.
func regReadBinary(root, name string) ([]byte, bool, error) {
	out, err := exec.Command("reg", "query", root, "/v", name, "/reg:64").Output()
	if err != nil {
		return nil, false, nil // missing (or unreadable) counts as absent
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		for j := 1; j+1 < len(fields); j++ {
			if !strings.EqualFold(fields[j], "REG_BINARY") {
				continue
			}
			tokens := append([]string(nil), fields[j+1:]...)
			for k := i + 1; k < len(lines); k++ {
				continueTokens := strings.Fields(lines[k])
				if len(continueTokens) == 0 || !allHexTokens(continueTokens) {
					break
				}
				tokens = append(tokens, continueTokens...)
			}
			data, err := hex.DecodeString(strings.Join(tokens, ""))
			if err != nil || len(data) == 0 {
				return nil, false, fmt.Errorf("slhwid: registry binary parse failed")
			}
			return data, true, nil
		}
	}
	return nil, false, nil
}

// allHexTokens reports whether every token is pure hex digits.
func allHexTokens(tokens []string) bool {
	for _, t := range tokens {
		if len(t) == 0 {
			return false
		}
		for _, c := range t {
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
	}
	return true
}

func regWriteBinary(root, name string, data []byte) error {
	hex := make([]byte, 0, len(data)*2)
	const digits = "0123456789abcdef"
	for _, b := range data {
		hex = append(hex, digits[b>>4], digits[b&0x0f])
	}
	return exec.Command("reg", "add", root, "/v", name, "/t", "REG_BINARY", "/d", string(hex), "/f", "/reg:64").Run()
}

func (s *registryStore) ReadSlstore() ([]byte, bool, error) {
	for _, root := range []string{regRootHKLM, regRootHKCU} {
		data, found, err := regReadBinary(root, slstoreName)
		if err != nil {
			return nil, false, err
		}
		if found {
			value, err := unwrapSlstore(data)
			if err != nil {
				return nil, false, err
			}
			return value, true, nil
		}
	}
	return nil, false, nil
}

func (s *registryStore) WriteSlstore(value []byte) error {
	blob := append(append([]byte(nil), slstorePrefix...), value...)
	if err := regWriteBinary(regRootHKLM, slstoreName, blob); err == nil {
		return nil
	}
	return regWriteBinary(regRootHKCU, slstoreName, blob)
}

func (s *registryStore) ReadHelper(id string) ([]byte, bool, error) {
	name := "HWID-" + id
	for _, root := range []string{regRootHKLM, regRootHKCU} {
		blob, found, err := regReadBinary(root, name)
		if err != nil {
			return nil, false, err
		}
		if found {
			return blob, true, nil
		}
	}
	return nil, false, nil
}

func (s *registryStore) WriteHelper(id string, blob []byte) error {
	name := "HWID-" + id
	if err := regWriteBinary(regRootHKLM, name, blob); err == nil {
		return nil
	}
	return regWriteBinary(regRootHKCU, name, blob)
}
