// Package slhwid implements a fault-tolerant secret-sharing HWID module. A
// random 244-bit key is shared across hardware
// factors with a threshold scheme, and the transmitted HWID is a
// domain-separated hash of that key. Ordinary hardware drift leaves the HWID
// unchanged; mandatory slots (by default the module's own persisted random
// value) can never be routed around.
//
// The module is opt-in (see the bedrock package's HWIDMode configuration)
// and can also be driven directly for custom flows:
//
//	session, err := slhwid.Prepare(slhwid.Options{})
//	// ... authenticate with session.HWID() ...
//	_ = session.Commit() // after the server accepted the authentication
package slhwid

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Options configures one Prepare call.
type Options struct {
	// StorePath optionally redirects module storage to a directory (files in
	// that directory are used on every platform). Empty uses the platform
	// default: the registry on Windows, a per-user application-support
	// directory elsewhere.
	StorePath string

	// ExtraMandatory names additional hard-locked slots beyond the default
	// "slstore" (for example "machine_guid").
	ExtraMandatory []string

	// ForceReenroll discards any stored helper data and enrolls a fresh key,
	// producing a new HWID. The application must then run its existing
	// server-side device-reset flow.
	ForceReenroll bool
}

// DriftError reports that the stored secret could not be recovered. Mandatory
// reports whether a hard-locked slot is the cause (changed or absent);
// Missing lists those slots. Present and Needed describe the drift budget.
type DriftError struct {
	Present   int
	Needed    int
	Missing   []string
	Mandatory bool
}

func (e *DriftError) Error() string {
	if e.Mandatory {
		return fmt.Sprintf("slhwid: mandatory factor(s) %s changed or absent; re-activation required", strings.Join(e.Missing, ", "))
	}
	return fmt.Sprintf("slhwid: hardware drifted past the recovery threshold (%d factors present, %d needed); re-activation required", e.Present, e.Needed)
}

// Session is one prepared secret-sharing HWID. HWID is available immediately;
// Commit persists a re-centered share set and must only be called after the
// server accepted the authentication that used the HWID.
type Session struct {
	store     store
	hwid      string
	fresh     bool
	drifted   []string
	pending   bool
	factors   map[string]string
	mandatory map[string]bool
	k         key
	hasK      bool
	rng       io.Reader
	committed bool
	expected  []byte
}

// Prepare collects factors and recovers (or enrolls) the secret-sharing HWID
// for the current device. Enrollment persists immediately; a recovered
// Session persists nothing until Commit.
func Prepare(opts Options) (*Session, error) {
	return prepareWith(opts, Collect, rand.Reader, nil)
}

// prepareWith is the testable core of Prepare: factor collection, randomness
// and storage are injected.
func prepareWith(opts Options, collect func() (map[string]string, error), rng io.Reader, st store) (*Session, error) {
	requestedMandatory := map[string]bool{"slstore": true}
	for _, name := range opts.ExtraMandatory {
		if !validSlotName(name) {
			return nil, fmt.Errorf("slhwid: invalid extra mandatory slot name %q", name)
		}
		requestedMandatory[name] = true
	}

	raw, err := collect()
	if err != nil {
		return nil, fmt.Errorf("slhwid: factor collection failed: %w", err)
	}
	rawFactors := normalizeFactors(raw)

	if st == nil {
		st, err = defaultStore(opts.StorePath)
		if err != nil {
			return nil, err
		}
	}
	id := deviceHelperID
	release, err := acquireStoreLock(st)
	if err != nil {
		return nil, err
	}
	defer release()

	blob, found, err := st.ReadHelper(id)
	if err != nil {
		return nil, fmt.Errorf("slhwid: helper storage read failed: %w", err)
	}

	session := &Session{
		store: st,
		rng:   rng,
	}

	// The slstore factor is ours, not collectable hardware: recovery injects
	// the persisted value (read-only). An absent value with an existing
	// helper is intentional tampering and recoverCore reports it as a
	// hard-locked mandatory failure below.
	if found && !opts.ForceReenroll && rawFactors["slstore"] == "" {
		value, ok, err := st.ReadSlstore()
		if err != nil {
			return nil, fmt.Errorf("slhwid: store secret read failed: %w", err)
		} else if ok {
			if len(value) != 32 {
				return nil, fmt.Errorf("%w: store secret has the wrong size", ErrCorruptHelper)
			}
			rawFactors["slstore"] = hex.EncodeToString(value)
		}
	}

	if !found || opts.ForceReenroll {
		// Enrollment creates the persisted store secret before any share
		// exists.
		if rawFactors["slstore"] == "" {
			value, err := ensureSlstore(st, rng)
			if err != nil {
				return nil, err
			}
			rawFactors["slstore"] = value
		}
		factors, err := projectFactors(rawFactors, currentNormVersion)
		if err != nil {
			return nil, err
		}
		mandatory := mapMandatoryToCurrent(requestedMandatory)
		for name := range mandatory {
			if factors[name] == "" {
				return nil, fmt.Errorf("slhwid: mandatory factor %q is not available on this machine", name)
			}
		}
		n := len(factors)
		m := len(mandatory)
		t, err := threshold(n, m)
		if err != nil {
			return nil, err
		}
		d := &draw{r: rng}
		var k key
		for l := 0; l < 4; l++ {
			if k[l], err = d.elem(); err != nil {
				return nil, err
			}
		}
		shares, salt, err := buildShares(k, slotList(factors, mandatory), t, d)
		if err != nil {
			return nil, err
		}
		cw := checkWord(k)
		blob = serializeHelper(shares, mandatory, t, salt, cw, currentNormVersion)
		wipe(cw)
		if err := st.WriteHelper(id, blob); err != nil {
			return nil, fmt.Errorf("slhwid: helper storage write failed: %w", err)
		}
		session.hwid = hwidOf(k)
		session.fresh = true
		session.k = k
		session.hasK = true
		session.factors = factors
		session.mandatory = mandatory
		session.expected = append([]byte(nil), blob...)
		return session, nil
	}

	helper, err := parseHelper(blob)
	if err != nil {
		return nil, fmt.Errorf("%w; re-enroll to recover", ErrCorruptHelper)
	}
	recoveryFactors, err := projectFactors(rawFactors, helper.normVersion)
	if err != nil {
		return nil, err
	}
	r := recoverCore(blob, recoveryFactors)
	if !r.ok {
		if r.reason == "corrupt" {
			return nil, fmt.Errorf("%w; re-enroll to recover", ErrCorruptHelper)
		}
		return nil, &DriftError{
			Present:   r.present,
			Needed:    r.needed,
			Missing:   r.missing,
			Mandatory: r.reason == "mandatory",
		}
	}
	session.expected = append([]byte(nil), blob...)
	// A second application must not weaken a hard lock selected by the
	// application that enrolled the shared device helper.
	storedMandatory := map[string]bool{}
	for _, slot := range helper.slots {
		if slot.mandatory {
			storedMandatory[slot.name] = true
		}
	}
	session.factors, err = projectFactors(rawFactors, currentNormVersion)
	if err != nil {
		return nil, err
	}
	session.mandatory = mapMandatoryToCurrent(storedMandatory)
	// Promoting an enrolled optional slot must not absorb a change to it.
	// Newly available slots are bound after authorization by Commit.
	deadSet := make(map[string]bool, len(r.dead))
	for _, name := range r.dead {
		deadSet[name] = true
	}
	changed := mapMandatoryToCurrent(deadSet)
	policyChanged := false
	var unavailable []string
	for name := range mapMandatoryToCurrent(requestedMandatory) {
		if session.mandatory[name] {
			continue
		}
		if session.factors[name] == "" || changed[name] {
			unavailable = append(unavailable, name)
			continue
		}
		session.mandatory[name] = true
		policyChanged = true
	}
	if len(unavailable) > 0 {
		r.k = key{} // best-effort zeroization of the unrecoverable key
		sort.Strings(unavailable)
		present := 0
		for _, slot := range helper.slots {
			if recoveryFactors[slot.name] != "" {
				present++
			}
		}
		return nil, &DriftError{
			Present:   present,
			Needed:    helper.threshold,
			Missing:   unavailable,
			Mandatory: true,
		}
	}
	if policyChanged && len(session.mandatory) >= len(session.factors) {
		r.k = key{}
		return nil, fmt.Errorf("slhwid: mandatory slots must be fewer than total factors")
	}
	session.hwid = r.hwid
	session.drifted = r.dead
	session.pending = r.pending || policyChanged
	session.k = r.k
	session.hasK = true
	return session, nil
}

// Commit re-shares the recovered key over the hardware observed at Prepare
// time with fresh randomness and persists the new helper data, re-centering
// fault tolerance on the machine's current factors. It must only be called
// after the server accepted the authentication using the session's HWID.
// Committing is idempotent per Session; skipped (with a nil error) when too
// few factors are currently available. Commit errors are recoverable: the
// next launch re-derives everything.
func (s *Session) Commit() error {
	if s.committed || !s.hasK {
		s.wipeSecret()
		return nil
	}
	s.committed = true
	defer s.wipeSecret()
	release, err := acquireStoreLock(s.store)
	if err != nil {
		return err
	}
	defer release()
	current, found, err := s.store.ReadHelper(deviceHelperID)
	if err != nil {
		return fmt.Errorf("slhwid: helper storage read failed: %w", err)
	}
	if !found || !bytes.Equal(current, s.expected) {
		// Another module user refreshed or re-enrolled after this session
		// prepared. Never overwrite its newer state with a stale snapshot.
		return nil
	}
	blob, ok, err := refreshCore(s.k, s.factors, s.mandatory, &draw{r: s.rng})
	if err != nil {
		return fmt.Errorf("slhwid: refresh failed: %w", err)
	}
	if ok {
		if err := s.store.WriteHelper(deviceHelperID, blob); err != nil {
			return fmt.Errorf("slhwid: helper storage write failed: %w", err)
		}
		s.pending = false
		s.drifted = nil
	}
	return nil
}

// HWID returns the transmitted device identifier (43 characters, base64url).
func (s *Session) HWID() string { return s.hwid }

// FreshlyEnrolled reports whether this session created a new key (a device
// the server has never seen).
func (s *Session) FreshlyEnrolled() bool { return s.fresh }

// DriftedSlots lists enrolled slots that were dead at Prepare time.
func (s *Session) DriftedSlots() []string { return s.drifted }

// PendingRefresh reports whether any slot was dead (Commit will re-center).
func (s *Session) PendingRefresh() bool { return s.pending }

func (s *Session) wipeSecret() {
	s.k = key{}
	s.hasK = false
}

// ensureSlstore loads the persisted store secret or creates it. The returned
// factor value is the lowercase hex of the 32 random bytes.
func ensureSlstore(st store, rng io.Reader) (string, error) {
	if value, found, err := st.ReadSlstore(); err != nil {
		return "", fmt.Errorf("slhwid: store secret read failed: %w", err)
	} else if found {
		if len(value) != 32 {
			return "", fmt.Errorf("%w: store secret has the wrong size", ErrCorruptHelper)
		}
		return hex.EncodeToString(value), nil
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(rng, value); err != nil {
		return "", fmt.Errorf("slhwid: randomness failed: %w", err)
	}
	if err := st.WriteSlstore(value); err != nil {
		return "", fmt.Errorf("slhwid: store secret write failed: %w", err)
	}
	encoded := hex.EncodeToString(value)
	wipe(value)
	return encoded, nil
}

var slotNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func validSlotName(name string) bool { return slotNamePattern.MatchString(name) }

const deviceHelperID = "device"

// store persists the module's own random value and the device helper blob.
// Implementations must read what any other Bedrock language wrote.
type store interface {
	// ReadSlstore returns the 32-byte store secret; found is false when it
	// does not exist yet.
	ReadSlstore() (value []byte, found bool, err error)
	WriteSlstore(value []byte) error
	// ReadHelper returns the stored shared-device helper blob; found is
	// false when none exists.
	ReadHelper(id string) (blob []byte, found bool, err error)
	WriteHelper(id string, blob []byte) error
}

type lockableStore interface {
	lock() (func(), error)
}

func acquireStoreLock(st store) (func(), error) {
	if lockable, ok := st.(lockableStore); ok {
		return lockable.lock()
	}
	return func() {}, nil // in-memory test stores are already isolated
}
