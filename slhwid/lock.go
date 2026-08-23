package slhwid

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	lockFileName     = ".slhwid.lock"
	lockHeader       = "SLHwidLockV1"
	lockWait         = 30 * time.Second
	unknownLockGrace = 2 * time.Minute
)

// acquireStorageLock uses an exclusive lock-file creation. The marker carries
// a random owner token so a delayed releaser cannot remove another process's
// replacement marker. A malformed or abandoned marker is reclaimed after a
// bounded grace period, preventing a crash from leaving permanent state.
func acquireStorageLock(directory string) (func(), error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("slhwid: storage lock directory unavailable: %w", err)
	}
	lockPath := filepath.Join(directory, lockFileName)
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("slhwid: storage lock randomness failed: %w", err)
	}
	contents := lockHeader + "\n" + strconv.Itoa(os.Getpid()) + "\n" + fmt.Sprintf("%x", token) + "\n"
	deadline := time.Now().Add(lockWait)

	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, writeErr := file.WriteString(contents)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				removeLockIfUnchanged(lockPath, contents)
				if writeErr != nil {
					return nil, fmt.Errorf("slhwid: storage lock write failed: %w", writeErr)
				}
				return nil, fmt.Errorf("slhwid: storage lock close failed: %w", closeErr)
			}
			return func() { removeLockIfUnchanged(lockPath, contents) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("slhwid: cannot acquire storage lock: %w", err)
		}

		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) >= unknownLockGrace {
			if existing, readErr := os.ReadFile(lockPath); readErr == nil {
				removeLockIfUnchanged(lockPath, string(existing))
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("slhwid: storage is busy; retry the operation")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func removeLockIfUnchanged(path, expected string) {
	data, err := os.ReadFile(path)
	if err == nil && string(data) == expected {
		_ = os.Remove(path)
	}
}

func localLockDirectory() (string, error) {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "SystemLocker"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "AppData", "Local", "SystemLocker"), nil
}
