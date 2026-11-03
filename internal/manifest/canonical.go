package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeUnique rejects ambiguous duplicate object keys, invalid UTF-8, null
// values (absent from this contract), unpaired surrogates and trailing data.
func decodeUnique(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	if err := rejectUnpairedSurrogates(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	result, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err == nil {
		return nil, errors.New("trailing JSON content")
	} else if err != io.EOF {
		return nil, err
	}
	return result, nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON exceeds nesting limit")
	}
	tok, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch val := tok.(type) {
	case nil:
		return nil, errors.New("null is not allowed in this contract")
	case json.Delim:
		switch val {
		case '{':
			obj := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := obj[name]; exists {
					return nil, fmt.Errorf("duplicate JSON key %q", name)
				}
				child, err := readValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				obj[name] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid object termination")
			}
			return obj, nil
		case '[':
			var values []any
			for decoder.More() {
				child, err := readValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				values = append(values, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid array termination")
			}
			return values, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	default:
		return val, nil
	}
}

func rejectUnpairedSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || i+1 >= len(data) {
				continue
			}
			if data[i+1] != 'u' {
				i++
				continue
			}
			if i+6 > len(data) {
				return errors.New("invalid unicode escape")
			}
			first, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
			if err != nil {
				return errors.New("invalid unicode escape")
			}
			if first >= 0xdc00 && first <= 0xdfff {
				return errors.New("unpaired low surrogate")
			}
			if first >= 0xd800 && first <= 0xdbff {
				if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
					return errors.New("unpaired high surrogate")
				}
				second, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
				if err != nil || second < 0xdc00 || second > 0xdfff {
					return errors.New("unpaired high surrogate")
				}
				i += 11
			} else {
				i += 5
			}
		}
	}
	return nil
}

// canonicalize implements the RFC 8785 string and UTF-16 property-ordering
// rules. This manifest contract contains only safe integer numeric fields.
func canonicalize(v any) ([]byte, error) {
	var result bytes.Buffer
	if err := writeCanonical(&result, v); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case map[string]any:
		names := make([]string, 0, len(value))
		for key := range value {
			names = append(names, key)
		}
		sort.Slice(names, func(i, j int) bool { return utf16Before(names[i], names[j]) })
		out.WriteByte('{')
		for i, key := range names {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case string:
		writeString(out, value)
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		f, err := strconv.ParseFloat(value.String(), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return errors.New("unsupported JSON number")
		}
		if f == 0 {
			out.WriteByte('0')
		} else if math.Trunc(f) == f && math.Abs(f) < 1e21 {
			out.WriteString(strconv.FormatFloat(f, 'f', 0, 64))
		} else {
			out.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
		}
	case float64:
		return writeCanonical(out, json.Number(strconv.FormatFloat(value, 'g', -1, 64)))
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", v)
	}
	return nil
}

func utf16Before(left, right string) bool {
	a := utf16.Encode([]rune(left))
	b := utf16.Encode([]rune(right))
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func writeString(out *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[(r>>4)&0xf])
				out.WriteByte(hexDigits[r&0xf])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func keysExact(v any, expected ...string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != len(expected) {
		return nil, errors.New("unexpected, missing, or invalid object field")
	}
	for _, key := range expected {
		if _, exists := obj[key]; !exists {
			return nil, fmt.Errorf("missing %s", key)
		}
	}
	return obj, nil
}

func ensureShape(root any) error {
	envelope, err := keysExact(root, "signatureVersion", "signerId", "contentDigest", "signature", "manifest")
	if err != nil {
		return err
	}
	for _, key := range []string{"signatureVersion", "signerId", "contentDigest", "signature"} {
		if _, ok := envelope[key].(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	manifest, err := keysExact(envelope["manifest"], "schemaVersion", "controlPlaneEpoch", "nodeId", "structuralSequence", "membershipSequence", "issuedAt", "expiresAt", "requiredCapabilities", "components", "baseEgressPolicy")
	if err != nil {
		return err
	}
	for _, key := range []string{"schemaVersion", "controlPlaneEpoch", "nodeId", "issuedAt", "expiresAt", "baseEgressPolicy"} {
		if _, ok := manifest[key].(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	for _, key := range []string{"structuralSequence", "membershipSequence"} {
		if err := checkPositiveInteger(manifest[key]); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	if err := checkStringArray(manifest["requiredCapabilities"], 1, 64); err != nil {
		return err
	}
	components, ok := manifest["components"].([]any)
	if !ok || len(components) == 0 || len(components) > 64 {
		return errors.New("components count invalid")
	}
	for _, raw := range components {
		component, err := keysExact(raw, "id", "driver", "runtimeVersion", "artifactDigest", "configurationDigest", "configurationRef", "dependsOn", "listeners", "disruption")
		if err != nil {
			return err
		}
		for _, key := range []string{"id", "driver", "runtimeVersion", "artifactDigest", "configurationDigest", "configurationRef", "disruption"} {
			if _, ok := component[key].(string); !ok {
				return fmt.Errorf("component %s must be string", key)
			}
		}
		if err := checkStringArray(component["dependsOn"], 0, 64); err != nil {
			return err
		}
		listeners, ok := component["listeners"].([]any)
		if !ok || len(listeners) > 64 {
			return errors.New("listeners count invalid")
		}
		for _, rawListener := range listeners {
			listener, err := keysExact(rawListener, "address", "port", "transport", "ipv6Only")
			if err != nil {
				return err
			}
			if _, ok := listener["address"].(string); !ok {
				return errors.New("address must be a string")
			}
			if _, ok := listener["transport"].(string); !ok {
				return errors.New("transport must be a string")
			}
			if _, ok := listener["ipv6Only"].(bool); !ok {
				return errors.New("ipv6Only must be boolean")
			}
			if err := checkPositiveInteger(listener["port"]); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkPositiveInteger(value any) error {
	number, ok := value.(json.Number)
	if !ok {
		return errors.New("expected integer")
	}
	if strings.ContainsAny(number.String(), ".eE+-") {
		return errors.New("non-decimal integer not accepted")
	}
	n, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || n > maxSafeInteger {
		return errors.New("unsafe integer")
	}
	return nil
}

func checkStringArray(value any, minimum, maximum int) error {
	elements, ok := value.([]any)
	if !ok || len(elements) < minimum || len(elements) > maximum {
		return errors.New("invalid string array")
	}
	for _, element := range elements {
		if _, ok := element.(string); !ok {
			return errors.New("non-string array element")
		}
	return nil
}
