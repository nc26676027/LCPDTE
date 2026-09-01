package treeplan

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"reflect"
)

// canonicalEncoder hashes the semantic numeric fields directly. It never
// calls JSON, encoding interfaces, reflection-based struct serialization, or
// user-defined marshal methods.
type canonicalEncoder struct {
	h       hash.Hash
	scratch [8]byte
}

func newCanonicalEncoder(domain string) *canonicalEncoder {
	encoder := &canonicalEncoder{h: sha256.New()}
	encoder.writeBytes([]byte(domain))
	return encoder
}

func (e *canonicalEncoder) writeBytes(value []byte) {
	e.writeUint64(uint64(len(value)))
	_, _ = e.h.Write(value)
}

func (e *canonicalEncoder) writeUint64(value uint64) {
	binary.BigEndian.PutUint64(e.scratch[:], value)
	_, _ = e.h.Write(e.scratch[:])
}

func (e *canonicalEncoder) writeInt(value int) {
	e.writeUint64(uint64(int64(value)))
}

func (e *canonicalEncoder) writeScalar(value any) error {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return fmt.Errorf("treeplan: invalid numeric scalar")
	}
	kind := v.Kind()
	_, _ = e.h.Write([]byte{byte(kind)})
	e.writeUint64(uint64(v.Type().Bits()))

	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// The two's-complement cast is injective once kind/width are included.
		e.writeUint64(uint64(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.writeUint64(v.Uint())
	case reflect.Float32:
		e.writeUint64(uint64(math.Float32bits(float32(v.Float()))))
	case reflect.Float64:
		e.writeUint64(math.Float64bits(v.Float()))
	default:
		return fmt.Errorf("treeplan: unsupported scalar kind %s", kind)
	}
	return nil
}

func (e *canonicalEncoder) sum() (result [sha256.Size]byte) {
	copy(result[:], e.h.Sum(nil))
	return
}

func digestBinaryTree[T Ordered, L Ordered](tree BinaryTree[T, L]) ([sha256.Size]byte, error) {
	e := newCanonicalEncoder("LCPDTE/treeplan/BinaryTree/v1")
	e.writeInt(tree.Depth)
	e.writeUint64(uint64(len(tree.Splits)))
	for _, split := range tree.Splits {
		e.writeInt(split.Feature)
		if err := e.writeScalar(split.Threshold); err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	e.writeUint64(uint64(len(tree.Leaves)))
	for _, leaf := range tree.Leaves {
		if err := e.writeScalar(leaf); err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	return e.sum(), nil
}

func digestRadixPlan[T Ordered, L Ordered](tree RadixTree[T, L]) ([sha256.Size]byte, error) {
	e := newCanonicalEncoder("LCPDTE/treeplan/RadixTree/v1")
	e.writeInt(tree.BinaryDepth)
	e.writeInt(tree.GroupWidth)
	e.writeUint64(uint64(len(tree.Levels)))
	for _, level := range tree.Levels {
		e.writeInt(level.StartDepth)
		e.writeInt(level.Width)
		e.writeUint64(uint64(len(level.Nodes)))
		for _, node := range level.Nodes {
			e.writeInt(node.Prefix)
			e.writeUint64(uint64(len(node.Splits)))
			for _, split := range node.Splits {
				e.writeInt(split.Feature)
				if err := e.writeScalar(split.Threshold); err != nil {
					return [sha256.Size]byte{}, err
				}
			}
		}
	}
	e.writeUint64(uint64(len(tree.Leaves)))
	for _, leaf := range tree.Leaves {
		if err := e.writeScalar(leaf); err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	return e.sum(), nil
}
