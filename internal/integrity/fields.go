package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

type FieldType uint8

const (
	FieldUTF8 FieldType = iota + 1
	FieldBytes
	FieldUint32
	FieldUint64
	FieldInt32
	FieldInt64
	FieldBool
	FieldUTF8List
	FieldBytes32
)

type TypedField struct {
	Tag   uint16
	Type  FieldType
	Value []byte
}

func EncodeFields(fields []TypedField) ([]byte, error) {
	if len(fields) > math.MaxUint16 {
		return nil, errors.New("too many typed fields")
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(len(fields)))
	var last uint16
	for i, f := range fields {
		if f.Tag == 0 || (i > 0 && f.Tag <= last) {
			return nil, errors.New("field tags must be nonzero and strictly increasing")
		}
		if err := validateFieldValue(f.Type, f.Value); err != nil {
			return nil, fmt.Errorf("field %d: %w", f.Tag, err)
		}
		if uint64(b.Len())+7+uint64(len(f.Value)) > maxFieldsBytes {
			return nil, errors.New("typed fields exceed 65536 bytes")
		}
		_ = binary.Write(&b, binary.BigEndian, f.Tag)
		b.WriteByte(byte(f.Type))
		_ = binary.Write(&b, binary.BigEndian, uint32(len(f.Value)))
		b.Write(f.Value)
		last = f.Tag
	}
	return b.Bytes(), nil
}

func DecodeFields(encoded []byte) ([]TypedField, error) {
	if len(encoded) < 2 || len(encoded) > maxFieldsBytes {
		return nil, errors.New("typed field encoding length must be 2..65536 bytes")
	}
	r := bytes.NewReader(encoded)
	var count uint16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, errors.New("truncated typed field count")
	}
	if int(count) > r.Len()/7 {
		return nil, errors.New("typed field count exceeds remaining encoding")
	}
	fields := make([]TypedField, 0, count)
	var last uint16
	for i := 0; i < int(count); i++ {
		var tag uint16
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
			return nil, errors.New("truncated typed field tag")
		}
		t, err := r.ReadByte()
		if err != nil {
			return nil, errors.New("truncated typed field type")
		}
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, errors.New("truncated typed field length")
		}
		if tag == 0 || (i > 0 && tag <= last) || uint64(n) > uint64(r.Len()) {
			return nil, errors.New("invalid typed field tag or length")
		}
		v := make([]byte, n)
		_, _ = r.Read(v)
		field := TypedField{Tag: tag, Type: FieldType(t), Value: v}
		if err := validateFieldValue(field.Type, field.Value); err != nil {
			return nil, fmt.Errorf("field %d: %w", tag, err)
		}
		fields = append(fields, field)
		last = tag
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing typed field bytes")
	}
	return fields, nil
}

func HashFields(fields []TypedField) (Hash, error) {
	b, err := EncodeFields(fields)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(b), nil
}

// StringList encodes a set of strings in canonical raw UTF-8 byte order.
func StringList(values []string) ([]byte, error) {
	items := append([]string(nil), values...)
	sort.Slice(items, func(i, j int) bool { return bytes.Compare([]byte(items[i]), []byte(items[j])) < 0 })
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(items)))
	for i, s := range items {
		if !validUTF8(s) || (i > 0 && items[i-1] == s) {
			return nil, errors.New("UTF-8 set must contain valid, unique strings")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	return b.Bytes(), nil
}

func validateFieldValue(t FieldType, v []byte) error {
	switch t {
	case FieldUTF8:
		if !validUTF8(string(v)) {
			return errors.New("invalid UTF-8 string or embedded NUL")
		}
	case FieldBytes:
	case FieldUint32, FieldInt32:
		if len(v) != 4 {
			return errors.New("32-bit field must contain exactly 4 bytes")
		}
	case FieldUint64, FieldInt64:
		if len(v) != 8 {
			return errors.New("64-bit field must contain exactly 8 bytes")
		}
	case FieldBool:
		if len(v) != 1 || v[0] > 1 {
			return errors.New("boolean field must be one byte 0 or 1")
		}
	case FieldUTF8List:
		if err := validateStringList(v); err != nil {
			return err
		}
	case FieldBytes32:
		if len(v) != 32 {
			return errors.New("bytes32 field must contain exactly 32 bytes")
		}
	default:
		return fmt.Errorf("unknown field type %d", t)
	}
	return nil
}

func validateStringList(v []byte) error {
	r := bytes.NewReader(v)
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return errors.New("truncated UTF-8 list count")
	}
	var previous []byte
	for i := uint32(0); i < n; i++ {
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil || uint64(length) > uint64(r.Len()) {
			return errors.New("invalid UTF-8 list item length")
		}
		item := make([]byte, length)
		_, _ = r.Read(item)
		if !utf8.Valid(item) || bytes.IndexByte(item, 0) >= 0 {
			return errors.New("invalid UTF-8 list item")
		}
		if i > 0 && bytes.Compare(previous, item) >= 0 {
			return errors.New("UTF-8 set items must be strictly sorted")
		}
		previous = item
	}
	if r.Len() != 0 {
		return errors.New("trailing UTF-8 list bytes")
	}
	return nil
}

func validUTF8(s string) bool { return utf8.ValidString(s) && bytes.IndexByte([]byte(s), 0) < 0 }

// ValidateKindFields enforces the frozen tag and type sets for one fact kind.
func ValidateKindFields(kind EntryKind, content, metadata []TypedField) error {
	contentSchema, metadataSchema, err := fieldSchemas(kind)
	if err != nil {
		return err
	}
	if err := validateSchema(content, contentSchema); err != nil {
		return fmt.Errorf("content: %w", err)
	}
	if err := validateSchema(metadata, metadataSchema); err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	return nil
}

type fieldSpec struct {
	typeID   FieldType
	optional bool
}

func validateSchema(fields []TypedField, schema map[uint16]fieldSpec) error {
	if _, err := EncodeFields(fields); err != nil {
		return err
	}
	for _, f := range fields {
		spec, ok := schema[f.Tag]
		if !ok || spec.typeID != f.Type {
			return fmt.Errorf("unexpected tag/type %d/%d", f.Tag, f.Type)
		}
	}
	for tag, spec := range schema {
		if spec.optional {
			continue
		}
		found := false
		for _, f := range fields {
			if f.Tag == tag {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required tag %d", tag)
		}
	}
	return nil
}

func fieldSchemas(kind EntryKind) (map[uint16]fieldSpec, map[uint16]fieldSpec, error) {
	utf8Field, bytes32, i64 := fieldSpec{typeID: FieldUTF8}, fieldSpec{typeID: FieldBytes32}, fieldSpec{typeID: FieldInt64}
	switch kind {
	case RawCommitted:
		m := map[uint16]fieldSpec{1: utf8Field, 2: utf8Field, 3: {typeID: FieldUint32}, 4: {typeID: FieldUint64}, 5: utf8Field, 6: utf8Field, 7: utf8Field, 8: utf8Field, 9: utf8Field, 10: i64, 11: utf8Field, 12: utf8Field, 13: utf8Field, 14: {typeID: FieldInt32}, 15: i64, 16: utf8Field}
		return emptySchema(), m, nil
	case NormalizedWritten:
		return emptySchema(), map[uint16]fieldSpec{1: utf8Field, 2: utf8Field, 3: bytes32, 4: utf8Field, 5: utf8Field}, nil
	case QuarantineWritten:
		return map[uint16]fieldSpec{1: bytes32, 2: utf8Field, 3: utf8Field, 4: utf8Field, 5: {typeID: FieldBytes}, 6: {typeID: FieldUTF8List}, 7: {typeID: FieldBool}, 8: i64, 9: {typeID: FieldInt64, optional: true}}, emptySchema(), nil
	case ReplayFailed:
		return map[uint16]fieldSpec{1: utf8Field, 2: bytes32, 3: {typeID: FieldBytes32, optional: true}}, emptySchema(), nil
	case ReplayResolved:
		return map[uint16]fieldSpec{1: {typeID: FieldUint64}, 2: {typeID: FieldUint64}}, map[uint16]fieldSpec{1: bytes32}, nil
	case NormalizedRemoved, QuarantineRemoved:
		return map[uint16]fieldSpec{1: {typeID: FieldUint64}, 2: utf8Field}, emptySchema(), nil
	default:
		return nil, nil, fmt.Errorf("unknown entry kind %d", kind)
	}
}

func emptySchema() map[uint16]fieldSpec { return map[uint16]fieldSpec{} }
