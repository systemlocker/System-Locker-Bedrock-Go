// core.go implements the §4A cryptographic core: GF(2^61-1) arithmetic on
// uint64, four-limb secret sharing, x-derivation, helper-blob serialization,
// recovery and refresh. Everything here is pure and platform-free; the
// lifecycle in slhwid.go wires it to collectors, storage and the CSPRNG.
package slhwid

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// prime is the field modulus 2^61-1.
const prime = uint64(1)<<61 - 1

// ErrCorruptHelper reports stored helper data that fails its integrity check
// or structural validation (distinct from hardware drift).
var ErrCorruptHelper = errors.New("slhwid: stored helper data is corrupt")

func addmod(a, b uint64) uint64 {
	s := a + b // a, b < prime < 2^61 → s < 2^62, no overflow
	if s >= prime {
		s -= prime
	}
	return s
}

func submod(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + prime - b
}

// red64 reduces any x < 2^64 into [0, prime): 2^61 ≡ 1 (mod prime).
func red64(x uint64) uint64 {
	r := (x & prime) + (x >> 61) // < 2^61 + 8
	if r >= prime {
		r -= prime
	}
	return r
}

// mulmod multiplies two field elements using 31/30-bit half splits so every
// intermediate product fits in uint64 (portable MSVC-safe form, no __int128).
func mulmod(a, b uint64) uint64 {
	const lo31 = uint64(0x7FFFFFFF)
	alo, ahi := a&lo31, a>>31 // alo < 2^31, ahi < 2^30
	blo, bhi := b&lo31, b>>31
	ll := alo * blo        // < 2^62
	t := alo*bhi + ahi*blo // < 2^62
	hh := ahi * bhi        // < 2^60
	// full product = ll + t·2^31 + hh·2^62, and 2^62 ≡ 2 (mod prime)
	th, tl := t>>31, t&lo31
	r := red64(ll)
	r = addmod(r, red64(tl<<31))
	r = addmod(r, red64(th<<1))
	r = addmod(r, red64(hh<<1))
	return r
}

// invmod returns a^(−1) mod prime (prime is prime and a ≠ 0).
func invmod(a uint64) uint64 {
	lm, hm := int64(1), int64(0)
	low, high := int64(a), int64(prime)
	for low > 1 {
		r := high / low
		lm, hm = hm-lm*r, lm
		low, high = high-low*r, low
	}
	if lm < 0 {
		lm += int64(prime)
	}
	return uint64(lm)
}

// draw replays an io.Reader (the CSPRNG in production, fixed streams in
// tests) as consecutive 8-byte little-endian field elements.
type draw struct {
	r io.Reader
}

func (d *draw) elem() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return 0, fmt.Errorf("slhwid: randomness exhausted: %w", err)
	}
	return binary.LittleEndian.Uint64(b[:]) % prime, nil
}

func deriveX(slot, value string, salt byte) uint64 {
	h := sha256.New()
	h.Write([]byte("SL-SS-X1"))
	h.Write([]byte{0, salt, 0})
	h.Write([]byte(slot))
	h.Write([]byte{0})
	h.Write([]byte(value))
	d := h.Sum(nil)
	v := binary.LittleEndian.Uint64(d[:8]) & prime
	return 1 + v%(prime-1)
}

// key is the 244-bit secret: four independent field elements.
type key [4]uint64

type share = key

func keyBytes(k key) []byte {
	out := make([]byte, 32)
	for i, l := range k {
		binary.LittleEndian.PutUint64(out[i*8:], l)
	}
	return out
}

func checkWord(k key) []byte {
	in := make([]byte, 0, 42)
	in = append(in, 0x01)
	in = append(in, []byte("SL-SS-CW1")...)
	in = append(in, keyBytes(k)...)
	s := sha256.Sum256(in)
	return s[:]
}

func hwidOf(k key) string {
	in := make([]byte, 0, 42)
	in = append(in, 0x02)
	in = append(in, []byte("SL-SS-ID1")...)
	in = append(in, keyBytes(k)...)
	s := sha256.Sum256(in)
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// ctEqual compares two secrets in constant time.
func ctEqual(a, b []byte) bool { return hmac.Equal(a, b) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// minimumFactors leaves one unavailable-collector margin below the
// conservative nine-slot physical-machine floor. Revisit it with every
// factor-schema change; it only governs new/current helpers, not v1 recovery.
const minimumFactors = 8

// threshold applies the §4A.2 rule: 80% below eight factors and 70% from
// eight upward, never below mandatory+1, with at least eight slots overall.
func threshold(n, m int) (int, error) {
	if n < minimumFactors {
		return 0, fmt.Errorf("slhwid: need at least %d enrolled factor slots, have %d", minimumFactors, n)
	}
	if m >= n {
		return 0, fmt.Errorf("slhwid: mandatory slots (%d) must be fewer than total (%d)", m, n)
	}
	num, den := 7, 10 // 8+ factors → 70%
	if n < 8 {
		num, den = 4, 5 // 5..7 factors → 80%
	}
	t := (num*n + den - 1) / den
	if t < m+1 {
		t = m + 1
	}
	if t > n {
		t = n
	}
	return t, nil
}

// ───────────────────────── normalization ─────────────────────────

// placeholders are junk values that count as "missing" (shared set with the
// legacy §4 hwid specification).
var placeholders = map[string]bool{
	"":                       true,
	"none":                   true,
	"unknown":                true,
	"default string":         true,
	"to be filled by o.e.m.": true,
	"not specified":          true,
	"system serial number":   true,
}

// normalize cleans a raw factor value exactly like the legacy hwid module:
// strip surrounding whitespace and NUL bytes, lowercase; MAC-derived values
// additionally drop ":" and "-". nic_identity may contain several permanent
// MAC addresses separated by "|", so it needs the same canonicalization.
func normalize(name, raw string) string {
	value := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "\x00", "")))
	if name == "mac" || name == "nic_identity" {
		value = strings.NewReplacer(":", "", "-", "").Replace(value)
	}
	return value
}

func isMissing(value string) bool { return placeholders[strings.TrimSpace(value)] }

// normalizeFactors normalizes every collected value and drops placeholders.
func normalizeFactors(raw map[string]string) map[string]string {
	out := make(map[string]string, len(raw))
	for name, value := range raw {
		nv := normalize(name, value)
		if nv == "" || isMissing(nv) {
			continue
		}
		out[name] = nv
	}
	return out
}

const (
	legacyNormVersion  byte = 1
	currentNormVersion byte = 2
)

var legacyFactorNames = []string{
	"slstore", "machine_guid", "product_uuid", "board_serial", "cpu_id",
	"disk_serial", "mac", "ram_total", "volume_id", "computer_name",
	"firmware", "gpu_id", "monitor_edid", "os_build",
}

var currentDirectFactorNames = []string{
	"slstore", "machine_guid", "cpu_id", "disk_serial", "ram_total",
	"volume_id", "firmware", "tpm_ek", "memory_modules", "nic_identity",
	"battery_serial",
}

type factorGroup struct {
	name    string
	members []string
}

var currentFactorGroups = []factorGroup{
	{name: "platform_identity", members: []string{"system_uuid", "board_serial", "system_serial", "chassis_serial"}},
	{name: "display_group", members: []string{"gpu_id", "monitor_edid"}},
	{name: "software_environment", members: []string{"computer_name", "os_build"}},
}

// projectFactors is the single maintenance point for factor-schema changes.
// Collectors return normalized raw signals. To add a direct factor, collect it
// on each supported platform and list it in currentDirectFactorNames. To add or
// change a group, edit currentFactorGroups. Removing/renaming a v1 factor must
// not change legacyFactorNames: old helpers still need their original inputs
// for recovery. Such changes require a new norm version and migration vectors.
func projectFactors(raw map[string]string, normVersion byte) (map[string]string, error) {
	out := map[string]string{}
	if normVersion == legacyNormVersion {
		for _, name := range legacyFactorNames {
			if value := raw[name]; value != "" {
				out[name] = value
			}
		}
		return out, nil
	}
	if normVersion != currentNormVersion {
		return nil, fmt.Errorf("slhwid: unsupported factor schema %d", normVersion)
	}
	for _, name := range currentDirectFactorNames {
		if value := raw[name]; value != "" {
			out[name] = value
		}
	}
	for _, group := range currentFactorGroups {
		if value := groupValue(group, raw); value != "" {
			out[group.name] = value
		}
	}
	return out, nil
}

// groupValue hashes a labelled, fixed-order encoding. Missing members are
// encoded as empty, so gaining or losing a member changes the one group slot;
// the group is omitted only when every member is absent.
func groupValue(group factorGroup, raw map[string]string) string {
	present := false
	h := sha256.New()
	h.Write([]byte("SL-HWID-GROUP2\x00"))
	h.Write([]byte(group.name))
	h.Write([]byte{0})
	for _, member := range group.members {
		value := raw[member]
		present = present || value != ""
		h.Write([]byte(member))
		h.Write([]byte{0})
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	if !present {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func currentMandatoryName(name string) string {
	switch name {
	case "product_uuid", "board_serial", "system_uuid", "system_serial", "chassis_serial":
		return "platform_identity"
	case "gpu_id", "monitor_edid":
		return "display_group"
	case "computer_name", "os_build":
		return "software_environment"
	case "mac":
		return "nic_identity"
	default:
		return name
	}
}

func mapMandatoryToCurrent(names map[string]bool) map[string]bool {
	out := map[string]bool{}
	for name, required := range names {
		if required {
			out[currentMandatoryName(name)] = true
		}
	}
	return out
}

// ───────────────────────── sharing ─────────────────────────

type slotData struct {
	name      string
	value     string
	mandatory bool
}

func slotList(factors map[string]string, mandatory map[string]bool) []slotData {
	names := make([]string, 0, len(factors))
	for name := range factors {
		names = append(names, name)
	}
	sort.Strings(names)
	slots := make([]slotData, 0, len(names))
	for _, name := range names {
		slots = append(slots, slotData{name: name, value: factors[name], mandatory: mandatory[name]})
	}
	return slots
}

// buildShares evaluates per-limb degree-(t-1) polynomials at every slot x.
// Coefficients come from the draw (limb-major, j = 1..t-1). The salt is
// bumped until all slot x-coordinates are pairwise distinct.
func buildShares(k key, slots []slotData, t int, d *draw) (map[string]share, byte, error) {
	salt := byte(0)
	xs := make([]uint64, len(slots))
	for {
		collision := false
		for i, s := range slots {
			xs[i] = deriveX(s.name, s.value, salt)
			for j := 0; j < i; j++ {
				if xs[i] == xs[j] {
					collision = true
				}
			}
		}
		if !collision {
			break
		}
		salt++
		if salt == 255 {
			return nil, 0, errors.New("slhwid: x-coordinate collision loop")
		}
	}
	var coeffs [4][]uint64
	for l := 0; l < 4; l++ {
		coeffs[l] = make([]uint64, t) // index j holds a_j; index 0 unused
		for j := 1; j < t; j++ {
			var err error
			if coeffs[l][j], err = d.elem(); err != nil {
				return nil, 0, err
			}
		}
	}
	shares := make(map[string]share, len(slots))
	for i, s := range slots {
		var y share
		for l := 0; l < 4; l++ {
			acc := uint64(0)
			for j := t - 1; j >= 1; j-- { // Horner
				acc = addmod(mulmod(acc, xs[i]), coeffs[l][j])
			}
			y[l] = addmod(mulmod(acc, xs[i]), k[l])
		}
		shares[s.name] = y
	}
	for l := 0; l < 4; l++ { // coefficients are secret-derived
		wipeU64(coeffs[l])
	}
	return shares, salt, nil
}

func wipeU64(v []uint64) {
	for i := range v {
		v[i] = 0
	}
}

// ───────────────────────── helper blob ─────────────────────────

const helperMagic = "SLSSHWID"

type helperData struct {
	normVersion byte
	salt        byte
	threshold   int
	slots       []helperSlot // sorted by name
	checkWord   []byte
}

type helperSlot struct {
	name      string
	mandatory bool
	share     share
}

func (h *helperData) mandatoryCount() int {
	m := 0
	for _, s := range h.slots {
		if s.mandatory {
			m++
		}
	}
	return m
}

func serializeHelper(shares map[string]share, mandatory map[string]bool, t int, salt byte, cw []byte, normVersion byte) []byte {
	names := make([]string, 0, len(shares))
	for name := range shares {
		names = append(names, name)
	}
	sort.Strings(names)

	var payload bytes.Buffer
	payload.WriteByte(1) // version
	payload.WriteByte(normVersion)
	payload.WriteByte(salt)
	payload.WriteByte(byte(len(names)))
	m := 0
	for _, name := range names {
		if mandatory[name] {
			m++
		}
	}
	payload.WriteByte(byte(m))
	payload.WriteByte(byte(t))
	payload.WriteByte(0) // reserved
	payload.WriteByte(0)
	for _, name := range names {
		payload.WriteByte(byte(len(name)))
		payload.WriteString(name)
		flag := byte(0)
		if mandatory[name] {
			flag = 1
		}
		payload.WriteByte(flag)
		for _, l := range shares[name] {
			var limb [8]byte
			binary.LittleEndian.PutUint64(limb[:], l)
			payload.Write(limb[:])
		}
	}

	var out bytes.Buffer
	out.WriteString(helperMagic)
	var lenb [4]byte
	binary.LittleEndian.PutUint32(lenb[:], uint32(payload.Len()))
	out.Write(lenb[:])
	out.Write(payload.Bytes())
	out.Write(cw)
	blob := out.Bytes()
	integrity := sha256.Sum256(blob)
	return append(blob, integrity[:]...)
}

func parseHelper(blob []byte) (*helperData, error) {
	if len(blob) < 8+4+8+32+32 {
		return nil, fmt.Errorf("%w: truncated", ErrCorruptHelper)
	}
	if string(blob[:8]) != helperMagic {
		return nil, fmt.Errorf("%w: magic mismatch", ErrCorruptHelper)
	}
	want := sha256.Sum256(blob[:len(blob)-32])
	if !ctEqual(want[:], blob[len(blob)-32:]) {
		return nil, fmt.Errorf("%w: integrity mismatch", ErrCorruptHelper)
	}
	payloadLen := int(binary.LittleEndian.Uint32(blob[8:12]))
	if 12+payloadLen+64 != len(blob) {
		return nil, fmt.Errorf("%w: length mismatch", ErrCorruptHelper)
	}
	body := blob[12 : 12+payloadLen]
	cw := blob[12+payloadLen : 12+payloadLen+32]
	if body[0] != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptHelper, body[0])
	}
	if body[1] != legacyNormVersion && body[1] != currentNormVersion {
		return nil, fmt.Errorf("%w: unsupported factor schema %d", ErrCorruptHelper, body[1])
	}
	h := &helperData{normVersion: body[1], salt: body[2], threshold: int(body[5]), checkWord: append([]byte(nil), cw...)}
	n := int(body[3])
	rest := body[8:]
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		if len(rest) < 1 {
			return nil, fmt.Errorf("%w: slot truncated", ErrCorruptHelper)
		}
		nameLen := int(rest[0])
		if nameLen == 0 || len(rest) < 1+nameLen+1+32 {
			return nil, fmt.Errorf("%w: slot truncated", ErrCorruptHelper)
		}
		name := string(rest[1 : 1+nameLen])
		if seen[name] {
			return nil, fmt.Errorf("%w: duplicate slot %q", ErrCorruptHelper, name)
		}
		seen[name] = true
		mandatory := rest[1+nameLen]&1 == 1
		var sh share
		for l := 0; l < 4; l++ {
			sh[l] = binary.LittleEndian.Uint64(rest[2+nameLen+l*8:])
			if sh[l] >= prime {
				return nil, fmt.Errorf("%w: share limb out of range", ErrCorruptHelper)
			}
		}
		h.slots = append(h.slots, helperSlot{name: name, mandatory: mandatory, share: sh})
		rest = rest[2+nameLen+32:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrCorruptHelper)
	}
	return h, nil
}

// ───────────────────────── recovery ─────────────────────────

type point struct {
	name string
	x    uint64
	sh   share
}

type recoverResult struct {
	ok      bool
	reason  string // "drift" | "mandatory" | "corrupt"
	k       key
	hwid    string
	live    []string
	dead    []string
	pending bool
	present int
	needed  int
	missing []string
}

func coords(pts []point, l int) (xs, ys []uint64) {
	xs = make([]uint64, len(pts))
	ys = make([]uint64, len(pts))
	for i, pt := range pts {
		xs[i], ys[i] = pt.x, pt.sh[l]
	}
	return
}

func keyFromPoints(pts []point) key {
	var k key
	for l := 0; l < 4; l++ {
		xs, ys := coords(pts, l)
		k[l] = lagrangeAt0(xs, ys)
	}
	return k
}

// lagrangeAt0 interpolates the limb value at x=0 from points (xs, ys):
// K = Σ_j y_j · Π_{k≠j} x_k·inv(x_k − x_j).
func lagrangeAt0(xs, ys []uint64) uint64 {
	var sum uint64
	for j := range xs {
		num, den := uint64(1), uint64(1)
		for k := range xs {
			if k == j {
				continue
			}
			num = mulmod(num, xs[k])
			den = mulmod(den, submod(xs[k], xs[j]))
		}
		sum = addmod(sum, mulmod(ys[j], mulmod(num, invmod(den))))
	}
	return sum
}

// evaluateAt interpolates the limb value at xq from points (xs, ys).
func evaluateAt(xs, ys []uint64, xq uint64) uint64 {
	var sum uint64
	for j := range xs {
		num, den := uint64(1), uint64(1)
		for k := range xs {
			if k == j {
				continue
			}
			num = mulmod(num, submod(xq, xs[k]))
			den = mulmod(den, submod(xs[j], xs[k]))
		}
		sum = addmod(sum, mulmod(ys[j], mulmod(num, invmod(den))))
	}
	return sum
}

// findRecoveringSubset searches size-t point subsets that include every
// mandatory candidate and optionally (need = t − |mandatory|) others, in
// lexicographic order, returning the first subset whose interpolation
// reproduces the check word. Mandatory slots are in every subset: a wrong
// mandatory factor cannot be routed around (hard lock).
//
// The sweep is exhaustive: neither intermediate failures nor a match
// truncate it, so the amount of work done does not signal which factors
// survived (side-channel resistance).
func findRecoveringSubset(mandatory, optional []point, t int, cw []byte) []point {
	need := t - len(mandatory)
	if need < 0 {
		need = 0
	}
	if need > len(optional) {
		return nil
	}
	var res []point
	var idx []int
	var dfs func(start int)
	dfs = func(start int) {
		if len(idx) == need {
			pts := append([]point(nil), mandatory...)
			for _, i := range idx {
				pts = append(pts, optional[i])
			}
			if res == nil && ctEqual(checkWord(keyFromPoints(pts)), cw) {
				res = pts
			}
			return
		}
		for i := start; i <= len(optional)-(need-len(idx)); i++ {
			idx = append(idx, i)
			dfs(i + 1)
			idx = idx[:len(idx)-1]
		}
	}
	dfs(0)
	return res
}

func recoverCore(blob []byte, factors map[string]string) recoverResult {
	h, err := parseHelper(blob)
	if err != nil {
		return recoverResult{ok: false, reason: "corrupt"}
	}
	t := h.threshold

	var mandatory, optional []point
	var missingMandatory []string
	present := 0
	for _, s := range h.slots {
		value, ok := factors[s.name]
		if !ok || value == "" {
			if s.mandatory {
				missingMandatory = append(missingMandatory, s.name)
			}
			continue
		}
		present++
		pt := point{name: s.name, x: deriveX(s.name, value, h.salt), sh: s.share}
		if s.mandatory {
			mandatory = append(mandatory, pt)
		} else {
			optional = append(optional, pt)
		}
	}
	// The sweep runs to completion regardless of absences or failures
	// (constant-work shape); the hard-locked mandatory verdict is applied
	// afterwards and any accidental match is discarded.
	found := findRecoveringSubset(mandatory, optional, t, h.checkWord)
	if len(missingMandatory) > 0 {
		return recoverResult{ok: false, reason: "mandatory", present: present, needed: t, missing: missingMandatory}
	}
	if found == nil {
		// Diagnostic: if dropping one mandatory slot lets the rest of the
		// machine recover, that mandatory factor was changed (intentional
		// tampering) rather than the machine having drifted. Every mandatory
		// slot is tested (no early exit); the first culprit in stored order
		// wins.
		culprit := ""
		for _, ms := range h.slots {
			if !ms.mandatory {
				continue
			}
			var mand2, opt2 []point
			for _, pt := range append(append([]point(nil), mandatory...), optional...) {
				if pt.name == ms.name {
					continue
				}
				if isMandatorySlot(h, pt.name) {
					mand2 = append(mand2, pt)
				} else {
					opt2 = append(opt2, pt)
				}
			}
			if culprit == "" && findRecoveringSubset(mand2, opt2, t, h.checkWord) != nil {
				culprit = ms.name
			}
		}
		if culprit != "" {
			return recoverResult{ok: false, reason: "mandatory", present: present, needed: t, missing: []string{culprit}}
		}
		return recoverResult{ok: false, reason: "drift", present: present, needed: t}
	}

	k := keyFromPoints(found)
	inSubset := map[string]bool{}
	for _, pt := range found {
		inSubset[pt.name] = true
	}
	var live, dead []string
	for _, s := range h.slots {
		if inSubset[s.name] {
			live = append(live, s.name)
			continue
		}
		value, ok := factors[s.name]
		if !ok || value == "" {
			dead = append(dead, s.name)
			continue
		}
		xq := deriveX(s.name, value, h.salt)
		onCurve := true
		for l := 0; l < 4; l++ {
			xs, ys := coords(found, l)
			if evaluateAt(xs, ys, xq) != s.share[l] {
				onCurve = false
				break
			}
		}
		if onCurve {
			live = append(live, s.name)
		} else {
			dead = append(dead, s.name)
		}
	}
	sort.Strings(live)
	sort.Strings(dead)
	return recoverResult{ok: true, k: k, hwid: hwidOf(k), live: live, dead: dead, pending: len(dead) > 0}
}

func isMandatorySlot(h *helperData, name string) bool {
	for _, s := range h.slots {
		if s.name == name {
			return s.mandatory
		}
	}
	return false
}

// refreshCore re-shares k over the current factors with fresh coefficients.
// It returns ok=false (skipped) when too few factors remain.
func refreshCore(k key, factors map[string]string, mandatory map[string]bool, d *draw) ([]byte, bool, error) {
	// A mapped v1 mandatory name (for example board_serial →
	// platform_identity) may be unavailable in the current projection. Do not
	// write a helper that silently drops that hard lock; keeping the old helper
	// lets a later successful authentication migrate it safely.
	for name := range mandatory {
		if factors[name] == "" {
			return nil, false, nil
		}
	}
	slots := slotList(factors, mandatory)
	m := 0
	for _, s := range slots {
		if s.mandatory {
			m++
		}
	}
	t, err := threshold(len(slots), m)
	if err != nil {
		return nil, false, nil
	}
	shares, salt, err := buildShares(k, slots, t, d)
	if err != nil {
		return nil, false, err
	}
	cw := checkWord(k)
	blob := serializeHelper(shares, mandatory, t, salt, cw, currentNormVersion)
	wipe(cw)
	return blob, true, nil
}
