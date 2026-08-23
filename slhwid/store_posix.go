// store_posix.go chooses the default storage directory on non-Windows
// platforms.
//go:build !windows

package slhwid

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func defaultStore(override string) (store, error) {
	if override != "" {
		return newDirStore(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("slhwid: home directory unavailable: %w", err)
	}
	if runtime.GOOS == "darwin" {
		override = filepath.Join(home, "Library", "Application Support", "SystemLocker")
	} else if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		override = filepath.Join(xdg, "systemlocker")
	} else {
		override = filepath.Join(home, ".local", "share", "systemlocker")
	}
	return newDirStore(override)
}
