package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// parsePlist decodes an XML property list (ioreg -a, diskutil -plist) into
// map[string]any / []any / string / int64 / float64 / bool / []byte / time.Time.
// plutil -convert json cannot be used because ioreg output contains <data>.
func parsePlist(b []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("plist: no value")
			}
			return nil, fmt.Errorf("plist: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return plistValue(dec, se)
		}
	}
}

func plistValue(dec *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					s, err := plistText(dec)
					if err != nil {
						return nil, err
					}
					key = s
					continue
				}
				v, err := plistValue(dec, t)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := plistValue(dec, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	s, err := plistText(dec)
	if err != nil {
		return nil, err
	}
	switch se.Name.Local {
	case "integer":
		s = strings.TrimSpace(s)
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			return n, nil
		}
		if n, err := strconv.ParseUint(s, 0, 64); err == nil {
			return int64(n), nil // large unsigned values (rare) wrap
		}
		return int64(0), nil
	case "real":
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	case "data":
		d, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		return d, nil
	case "date":
		t, _ := time.Parse(time.RFC3339, strings.TrimSpace(s))
		return t, nil
	}
	return s, nil // string and unknown types
}

// plistText reads character data up to the matching end element.
func plistText(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return sb.String(), nil
			}
			depth--
		}
	}
}

// plist accessors
func pStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func pInt(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

func pBool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func pMaps(m map[string]any, k string) []map[string]any {
	a, _ := m[k].([]any)
	out := make([]map[string]any, 0, len(a))
	for _, v := range a {
		if mm, ok := v.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}
