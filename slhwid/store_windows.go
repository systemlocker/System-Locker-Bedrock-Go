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

type registryStore struct{ selectedRoot string }

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

// selectRoot pins one helper and its mandatory SLStore to a coherent hive.
// Complete pairs win (HKLM before HKCU); partial pairs are deliberately kept
// partial so recovery never combines state from different enrollments.
func (s *registryStore) selectRoot(helperName string) (string, error) {
	if s.selectedRoot != "" {
		return s.selectedRoot, nil
	}
	lmStore, lmStoreFound, err := regReadBinary(regRootHKLM, slstoreName)
	_ = lmStore
	if err != nil {
		return "", err
	}
	cuStore, cuStoreFound, err := regReadBinary(regRootHKCU, slstoreName)
	_ = cuStore
	if err != nil {
		return "", err
	}
	var lmHelperFound, cuHelperFound bool
	if helperName != "" {
		_, lmHelperFound, err = regReadBinary(regRootHKLM, helperName)
		if err != nil {
			return "", err
		}
		_, cuHelperFound, err = regReadBinary(regRootHKCU, helperName)
		if err != nil {
			return "", err
		}
	}
	switch {
	case helperName != "" && lmHelperFound && lmStoreFound || helperName == "" && lmStoreFound:
		s.selectedRoot = regRootHKLM
	case helperName != "" && cuHelperFound && cuStoreFound || helperName == "" && cuStoreFound:
		s.selectedRoot = regRootHKCU
	case lmHelperFound || lmStoreFound:
		s.selectedRoot = regRootHKLM
	case cuHelperFound || cuStoreFound:
		s.selectedRoot = regRootHKCU
	}
	return s.selectedRoot, nil
}

func (s *registryStore) writePinned(name string, data []byte) error {
	root, err := s.selectRoot("")
	if err != nil {
		return err
	}
	if root != "" {
		return regWriteBinary(root, name, data)
	}
	if err := regWriteBinary(regRootHKLM, name, data); err == nil {
		s.selectedRoot = regRootHKLM
		return nil
	}
	if err := regWriteBinary(regRootHKCU, name, data); err == nil {
		s.selectedRoot = regRootHKCU
		return nil
	} else {
		return err
	}
}

func (s *registryStore) ReadSlstore() ([]byte, bool, error) {
	root, err := s.selectRoot("")
	if err != nil {
		return nil, false, err
	}
	if root == "" {
		return nil, false, nil
	}
	data, found, err := regReadBinary(root, slstoreName)
	if err != nil || !found {
		return nil, false, err
	}
	value, err := unwrapSlstore(data)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s *registryStore) WriteSlstore(value []byte) error {
	blob := append(append([]byte(nil), slstorePrefix...), value...)
	return s.writePinned(slstoreName, blob)
}

func (s *registryStore) ReadHelper(id string) ([]byte, bool, error) {
	name := "HWID-" + id
	root, err := s.selectRoot(name)
	if err != nil {
		return nil, false, err
	}
	if root == "" {
		return nil, false, nil
	}
	return regReadBinary(root, name)
}

func (s *registryStore) WriteHelper(id string, blob []byte) error {
	name := "HWID-" + id
	return s.writePinned(name, blob)
}
