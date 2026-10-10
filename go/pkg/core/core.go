// Package core provides schema canonicalization and hashing functionality for SchemaPin.
//
// It implements the schemapin-v1 canonical JSON serialization specified in
// TECHNICAL_SPECIFICATION.md section 4. The rules are strict so that every SDK
// produces byte-identical output:
//
//   - Object keys are sorted by Unicode code point (bytewise order of their
//     UTF-8 encoding).
//   - Duplicate object keys, NaN/Infinity, lone surrogates and invalid UTF-8
//     are rejected -- they have no canonical form.
//   - Strings are escaped minimally: '"' and '\' are backslash-escaped,
//     U+0008/U+000C/U+000A/U+000D/U+0009 use \b \f \n \r \t, the remaining C0
//     controls use lowercase \u00xx, and everything else (including '<', '>',
//     '&', U+007F, U+2028 and U+2029) is emitted literally. This is done by
//     hand rather than via encoding/json, whose HTML escaping and
//     toolchain-dependent \b/\f handling both diverge from the other SDKs.
//   - Numbers are IEEE-754 binary64. Any value whose magnitude exceeds
//     2**53 - 1 is rejected. Integral values are emitted as plain decimal
//     integers (-0 -> 0); non-integral values use ECMAScript Number::toString
//     (RFC 8785 section 3.2.2.3).
package core

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSafeInteger is the largest integer magnitude accepted by the canonicalizer (2**53 - 1).
const MaxSafeInteger = 9007199254740991

const maxDepth = 512

// ErrCanonicalization wraps every canonicalization / strict-parse failure so
// callers can test for it with errors.Is.
var ErrCanonicalization = errors.New("canonicalization error")

func canonErr(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCanonicalization, fmt.Sprintf(format, args...))
}

// SchemaPinCore provides schema canonicalization and hashing
type SchemaPinCore struct{}

// NewSchemaPinCore creates a new SchemaPinCore instance
func NewSchemaPinCore() *SchemaPinCore {
	return &SchemaPinCore{}
}

// CanonicalizeSchema converts a schema to its canonical string representation
// per schemapin-v1 (see the package documentation for the normative rules).
func (s *SchemaPinCore) CanonicalizeSchema(schema map[string]interface{}) (string, error) {
	if schema == nil {
		return "", canonErr("schema cannot be nil")
	}
	return CanonicalizeValue(schema)
}

// CanonicalizeValue canonicalizes any JSON-compatible Go value (maps, slices,
// strings, bools, nil, numeric types, json.Number, or any value that
// encoding/json can marshal).
func CanonicalizeValue(v interface{}) (string, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, v, 0); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// HashCanonical computes SHA-256 hash of canonical schema string
func (s *SchemaPinCore) HashCanonical(canonical string) []byte {
	hash := sha256.Sum256([]byte(canonical))
	return hash[:]
}

// CanonicalizeAndHash combines canonicalization and hashing in one step
func (s *SchemaPinCore) CanonicalizeAndHash(schema map[string]interface{}) ([]byte, error) {
	canonical, err := s.CanonicalizeSchema(schema)
	if err != nil {
		return nil, err
	}
	return s.HashCanonical(canonical), nil
}

// ValidateSchema performs basic validation on a schema: it must canonicalize.
func (s *SchemaPinCore) ValidateSchema(schema map[string]interface{}) error {
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}
	if _, err := s.CanonicalizeSchema(schema); err != nil {
		return fmt.Errorf("schema is not canonicalizable: %w", err)
	}
	return nil
}

// NormalizeSchema ensures schema is in a consistent format
func (s *SchemaPinCore) NormalizeSchema(schema map[string]interface{}) (map[string]interface{}, error) {
	if err := s.ValidateSchema(schema); err != nil {
		return nil, err
	}
	return schema, nil
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

func writeCanonical(sb *strings.Builder, v interface{}, depth int) error {
	if depth > maxDepth {
		return canonErr("nesting depth exceeds limit")
	}
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		return writeCanonicalString(sb, x)
	case float64:
		return writeFloat(sb, x)
	case float32:
		return writeFloat(sb, float64(x))
	case int:
		return writeInt(sb, int64(x))
	case int8:
		return writeInt(sb, int64(x))
	case int16:
		return writeInt(sb, int64(x))
	case int32:
		return writeInt(sb, int64(x))
	case int64:
		return writeInt(sb, x)
	case uint:
		return writeUint(sb, uint64(x))
	case uint8:
		return writeUint(sb, uint64(x))
	case uint16:
		return writeUint(sb, uint64(x))
	case uint32:
		return writeUint(sb, uint64(x))
	case uint64:
		return writeUint(sb, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return canonErr("malformed number %q", string(x))
		}
		return writeFloat(sb, f)
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // bytewise == code point order for valid UTF-8
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonicalString(sb, k); err != nil {
				return err
			}
			sb.WriteByte(':')
			if err := writeCanonical(sb, x[k], depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case []interface{}:
		sb.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, item, depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	default:
		// Structs, typed maps/slices, etc.: round-trip through encoding/json
		// and the strict parser so the same rules apply.
		raw, err := json.Marshal(v)
		if err != nil {
			return canonErr("unsupported value: %v", err)
		}
		parsed, err := ParseSchemaJSON(raw)
		if err != nil {
			return err
		}
		return writeCanonical(sb, parsed, depth+1)
	}
	return nil
}

func writeInt(sb *strings.Builder, i int64) error {
	if i > MaxSafeInteger || i < -MaxSafeInteger {
		return canonErr("integer %d exceeds the 2**53-1 safe range", i)
	}
	sb.WriteString(strconv.FormatInt(i, 10))
	return nil
}

func writeUint(sb *strings.Builder, u uint64) error {
	if u > MaxSafeInteger {
		return canonErr("integer %d exceeds the 2**53-1 safe range", u)
	}
	sb.WriteString(strconv.FormatUint(u, 10))
	return nil
}

func writeFloat(sb *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return canonErr("NaN and Infinity are not valid JSON")
	}
	if math.Abs(f) > MaxSafeInteger {
		return canonErr("number %v exceeds the 2**53-1 safe range", f)
	}
	if f == math.Trunc(f) {
		sb.WriteString(strconv.FormatInt(int64(f), 10)) // also maps -0 to 0
		return nil
	}
	sb.WriteString(es6NumberToString(f))
	return nil
}

// es6NumberToString formats a finite, non-integral float64 exactly as
// ECMAScript Number::toString would (RFC 8785 section 3.2.2.3).
func es6NumberToString(f float64) string {
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip digits in d.ddddde±xx form.
	text := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(text, "e")
	exp, _ := strconv.Atoi(expStr)
	intPart, fracPart, _ := strings.Cut(mant, ".")
	digits := strings.TrimLeft(intPart+fracPart, "0")
	exp -= len(fracPart)
	trimmed := strings.TrimRight(digits, "0")
	exp += len(digits) - len(trimmed)
	digits = trimmed
	k := len(digits)
	n := exp + k

	var body string
	switch {
	case n > 0 && n <= 21:
		body = digits[:n] + "." + digits[n:]
	case n > -6 && n <= 0:
		body = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		if k == 1 {
			body = digits + "e" + sign + strconv.Itoa(e)
		} else {
			body = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if neg {
		return "-" + body
	}
	return body
}

const hexDigits = "0123456789abcdef"

func writeCanonicalString(sb *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return canonErr("string is not valid UTF-8")
	}
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexDigits[r>>4])
				sb.WriteByte(hexDigits[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return nil
}

// ---------------------------------------------------------------------------
// Strict parser
// ---------------------------------------------------------------------------

// ParseSchemaJSON parses JSON text strictly for canonicalization. It rejects
// duplicate object keys, NaN/Infinity, numbers outside the 2**53-1 safe
// range, lone surrogates, invalid UTF-8 and unescaped control characters.
// Objects decode to map[string]interface{}, arrays to []interface{} and
// numbers to float64 (every accepted number is exactly representable or is a
// non-integral value whose binary64 rounding is what every SDK uses).
func ParseSchemaJSON(data []byte) (interface{}, error) {
	if !utf8.Valid(data) {
		return nil, canonErr("input is not valid UTF-8")
	}
	p := &strictParser{data: data}
	p.skipWs()
	v, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipWs()
	if p.pos != len(p.data) {
		return nil, p.fail("trailing characters")
	}
	return v, nil
}

// ParseSchemaObject is ParseSchemaJSON restricted to a top-level JSON object.
func ParseSchemaObject(data []byte) (map[string]interface{}, error) {
	v, err := ParseSchemaJSON(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return nil, canonErr("top-level JSON value must be an object")
	}
	return obj, nil
}

type strictParser struct {
	data []byte
	pos  int
}

func (p *strictParser) fail(msg string) error {
	return canonErr("invalid JSON at offset %d: %s", p.pos, msg)
}

func (p *strictParser) skipWs() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *strictParser) parseValue(depth int) (interface{}, error) {
	if depth > maxDepth {
		return nil, p.fail("nesting depth exceeds limit")
	}
	if p.pos >= len(p.data) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject(depth)
	case c == '[':
		return p.parseArray(depth)
	case c == '"':
		return p.parseString()
	case c == 't':
		return p.parseLiteral("true", true)
	case c == 'f':
		return p.parseLiteral("false", false)
	case c == 'n':
		return p.parseLiteral("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, p.fail(fmt.Sprintf("unexpected character %q", c))
	}
}

func (p *strictParser) parseLiteral(word string, v interface{}) (interface{}, error) {
	if strings.HasPrefix(string(p.data[p.pos:]), word) {
		p.pos += len(word)
		return v, nil
	}
	return nil, p.fail("expected " + word)
}

func (p *strictParser) parseNumber() (interface{}, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return nil, p.fail("malformed number")
	}
	if p.data[p.pos] == '0' {
		p.pos++
	} else if p.data[p.pos] >= '1' && p.data[p.pos] <= '9' {
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return nil, p.fail("malformed number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, p.fail("malformed number")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, p.fail("malformed number")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	text := string(p.data[start:p.pos])
	f, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, p.fail("malformed number")
	}
	if math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) > MaxSafeInteger {
		return nil, canonErr("number %s exceeds the 2**53-1 safe range", text)
	}
	return f, nil
}

func (p *strictParser) parseHex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.fail("invalid \\u escape")
	}
	v, err := strconv.ParseUint(string(p.data[p.pos:p.pos+4]), 16, 32)
	if err != nil {
		return 0, p.fail("invalid \\u escape")
	}
	p.pos += 4
	return rune(v), nil
}

func (p *strictParser) parseString() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c < 0x20:
			return "", p.fail("unescaped control character in string")
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.fail("unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				hi, err := p.parseHex4()
				if err != nil {
					return "", err
				}
				if hi >= 0xD800 && hi <= 0xDBFF {
					if p.pos+2 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", p.fail("lone high surrogate escape")
					}
					p.pos += 2
					lo, err := p.parseHex4()
					if err != nil {
						return "", err
					}
					if lo < 0xDC00 || lo > 0xDFFF {
						return "", p.fail("lone high surrogate escape")
					}
					sb.WriteRune((hi-0xD800)<<10 + (lo - 0xDC00) + 0x10000)
				} else if hi >= 0xDC00 && hi <= 0xDFFF {
					return "", p.fail("lone low surrogate escape")
				} else {
					sb.WriteRune(hi)
				}
			default:
				return "", p.fail(fmt.Sprintf("invalid escape \\%c", e))
			}
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail("invalid UTF-8 in string")
			}
			sb.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

func (p *strictParser) parseArray(depth int) (interface{}, error) {
	p.pos++ // [
	out := []interface{}{}
	p.skipWs()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWs()
		v, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWs()
		if p.pos >= len(p.data) {
			return nil, p.fail("expected , or ]")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return out, nil
		default:
			return nil, p.fail("expected , or ]")
		}
	}
}

func (p *strictParser) parseObject(depth int) (interface{}, error) {
	p.pos++ // {
	out := map[string]interface{}{}
	p.skipWs()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.skipWs()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail("expected string key")
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		p.skipWs()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail("expected :")
		}
		p.pos++
		p.skipWs()
		v, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, canonErr("duplicate object key %q", key)
		}
		out[key] = v
		p.skipWs()
		if p.pos >= len(p.data) {
			return nil, p.fail("expected , or }")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return out, nil
		default:
			return nil, p.fail("expected , or }")
		}
	}
}
