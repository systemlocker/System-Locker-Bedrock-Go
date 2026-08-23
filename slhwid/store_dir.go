// store_dir.go implements the directory-backed store used on every platform
// when SLHwidStore is configured explicitly.
package slhwid

import (
	"fmt"
	"os"
	"path/filepath"
)

var slstorePrefix = []byte("SLSTOR1")

type dirStore struct{ dir string }

func newDirStore(dir string) (store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("slhwid: store directory unavailable: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("slhwid: cannot secure store directory: %w", err)
	}
	return &dirStore{dir: dir}, nil
}

func writeFileExclusive(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600) // tighten pre-existing files too
}

func (s *dirStore) lock() (func(), error) { return acquireStorageLock(s.dir) }

// unwrapSlstore validates the "SLSTOR1" prefix and returns the raw secret.
func unwrapSlstore(data []byte) ([]byte, error) {
	if len(data) != len(slstorePrefix)+32 {
		return nil, fmt.Errorf("%w: store secret has the wrong size", ErrCorruptHelper)
	}
	for i, b := range slstorePrefix {
		if data[i] != b {
			return nil, fmt.Errorf("%w: store secret prefix mismatch", ErrCorruptHelper)
		}
	}
	return data[len(slstorePrefix):], nil
}

func (s *dirStore) ReadSlstore() ([]byte, bool, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "slstore.bin"))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := unwrapSlstore(data)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s *dirStore) WriteSlstore(value []byte) error {
	blob := append(append([]byte(nil), slstorePrefix...), value...)
	return writeFileExclusive(filepath.Join(s.dir, "slstore.bin"), blob)
}

func (s *dirStore) ReadHelper(id string) ([]byte, bool, error) {
	blob, err := os.ReadFile(filepath.Join(s.dir, "hwid-"+id+".bin"))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return blob, true, nil
}

func (s *dirStore) WriteHelper(id string, blob []byte) error {
	return writeFileExclusive(filepath.Join(s.dir, "hwid-"+id+".bin"), blob)
}
