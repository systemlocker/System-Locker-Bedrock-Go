// Package hwid derives a stable device identifier from hardware factors,
// following the shared System Locker HWID specification: factors are
// normalized, wrapped as factor=<name>|value=<value>, joined in a fixed
// order, and hashed with SHA-256 (base64url, unpadded).
package hwid

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// factorOrder is the canonical composition order from the specification.
var factorOrder = []string{
	"machine_guid",
	"product_uuid",
	"board_serial",
	"cpu_id",
	"disk_serial",
	"mac",
}

// placeholders are SMBIOS junk values that must count as "missing".
var placeholders = map[string]bool{
	"":                       true,
	"none":                   true,
	"unknown":                true,
	"default string":         true,
	"to be filled by o.e.m.": true,
	"not specified":          true,
	"system serial number":   true,
}

// normalize cleans a raw factor value: trims whitespace and NUL bytes and
// lowercases. MAC values additionally drop ":" and "-" separators; other
// factors (UUIDs, machine IDs) keep theirs.
func normalize(name, raw string) string {
	value := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "\x00", "")))
	if name == "mac" {
		value = strings.NewReplacer(":", "", "-", "").Replace(value)
	}
	return value
}

// isMissing reports whether a normalized value is a known placeholder.
func isMissing(value string) bool {
	return placeholders[strings.TrimSpace(value)]
}

// CanonicalString builds the canonical factor string from collected factors.
// Factors absent from the map (or holding placeholder values) contribute
// nothing.
func CanonicalString(factors map[string]string) string {
	var parts []string
	for _, name := range factorOrder {
		raw, present := factors[name]
		if !present {
			continue
		}
		value := normalize(name, raw)
		if value == "" || isMissing(value) {
			continue
		}
		parts = append(parts, "factor="+name+"|value="+value)
	}
	return strings.Join(parts, "&")
}

// FromCanonical hashes a canonical string into the final HWID.
func FromCanonical(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Compose derives an HWID from collected factors.
func Compose(factors map[string]string) string {
	return FromCanonical(CanonicalString(factors))
}
