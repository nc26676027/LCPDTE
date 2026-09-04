package secureeval

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring/ringqp"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

const (
	gaoFactorStoreVersion        = uint32(1)
	gaoFactorStoreHeaderMaxBytes = uint64(4 << 20)
	gaoFactorStoreBufferBytes    = 1 << 20
)

var gaoFactorStoreMagic = [8]byte{'L', 'C', 'P', 'D', 'T', 'E', 'F', '1'}

type gaoFullPackedFactorStore struct {
	params        ckks.Parameters
	literal       dft.MatrixLiteral
	directory     string
	factorCount   int
	factorPaths   []string
	factorSizes   []int64
	resident      []ltcommon.LinearTransformation
	validated     []dft.ValidatedFactor
	residentReady []bool
	diskLoads     []uint64
	residentBytes uint64
	closed        bool
}

type gaoFactorFileHeader struct {
	Version                   uint32   `json:"version"`
	Index                     int      `json:"index"`
	Count                     int      `json:"count"`
	Literal                   []byte   `json:"literal"`
	MetaData                  []byte   `json:"metadata"`
	LogBabyStepGiantStepRatio int      `json:"log_bsgs_ratio"`
	N1                        int      `json:"n1"`
	LevelQ                    int      `json:"level_q"`
	LevelP                    int      `json:"level_p"`
	Keys                      []int    `json:"keys"`
	PolySizes                 []uint64 `json:"poly_sizes"`
}

// newGaoFullPackedFactorStore writes every encoded factor to a private
// temporary directory and initially retains only file names and sizes in
// memory. PrepareResident later loads the factors once and removes that
// backing directory. With an empty parent, os.MkdirTemp selects the platform
// temporary filesystem (/tmp for the WSL acceptance runner).
func newGaoFullPackedFactorStore(
	params ckks.Parameters,
	literal dft.MatrixLiteral,
	encoder *ckks.Encoder,
	parent, label string,
) (store *gaoFullPackedFactorStore, err error) {
	if label == "" {
		label = "matrix"
	}
	directory, err := os.MkdirTemp(parent, "lcpdte-gao-dft-"+label+"-")
	if err != nil {
		return nil, fmt.Errorf("secureeval: create Gao DFT factor store: %w", err)
	}
	store = &gaoFullPackedFactorStore{
		params: params, literal: cloneGaoFullPackedFactorLiteral(literal), directory: directory,
	}
	ownedStore := store
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.Join(err, fmt.Errorf("secureeval: build Gao DFT factor store panicked: %v", recovered))
		}
		if err != nil {
			_ = ownedStore.Close()
			store = nil
		}
	}()

	err = dft.ForEachEncodedMatrixFactor(
		params, literal, encoder, encoderPrecision(encoder),
		func(index, count int, factor ltcommon.LinearTransformation) error {
			path := filepath.Join(directory, fmt.Sprintf("factor-%03d.bin", index))
			size, writeErr := writeGaoFactorFile(path, literal, index, count, factor)
			if writeErr != nil {
				return writeErr
			}
			store.factorPaths = append(store.factorPaths, path)
			store.factorSizes = append(store.factorSizes, size)
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("secureeval: build Gao DFT factor store: %w", err)
	}
	if len(store.factorPaths) != literal.Depth(false) {
		return nil, fmt.Errorf("secureeval: Gao DFT factor count is %d, want %d", len(store.factorPaths), literal.Depth(false))
	}
	store.factorCount = len(store.factorPaths)
	store.resident = make([]ltcommon.LinearTransformation, len(store.factorPaths))
	store.validated = make([]dft.ValidatedFactor, len(store.factorPaths))
	store.residentReady = make([]bool, len(store.factorPaths))
	store.diskLoads = make([]uint64, len(store.factorPaths))
	return store, nil
}

func encoderPrecision(encoder *ckks.Encoder) uint {
	if encoder == nil {
		return 0
	}
	return encoder.Prec()
}

func (s *gaoFullPackedFactorStore) Literal() dft.MatrixLiteral {
	if s == nil {
		return dft.MatrixLiteral{}
	}
	return cloneGaoFullPackedFactorLiteral(s.literal)
}

func (s *gaoFullPackedFactorStore) FactorCount() int {
	if s == nil || s.closed {
		return 0
	}
	return s.factorCount
}

// PrepareResident loads and validates every factor exactly once, then removes
// the private backing directory. After it succeeds, both ReadFactor and
// ReadValidatedFactor are pure in-memory lookups. Calling it again is a no-op.
func (s *gaoFullPackedFactorStore) PrepareResident() error {
	if s == nil || s.closed {
		return fmt.Errorf("secureeval: Gao DFT factor store is nil or closed")
	}
	for index := 0; index < s.factorCount; index++ {
		if err := s.loadResidentFactor(index); err != nil {
			return fmt.Errorf("secureeval: prepare resident Gao DFT factor %d: %w", index, err)
		}
	}
	if s.directory == "" {
		return nil
	}
	if err := os.RemoveAll(s.directory); err != nil {
		return fmt.Errorf("secureeval: remove resident Gao DFT backing store: %w", err)
	}
	s.directory = ""
	s.factorPaths = nil
	s.factorSizes = nil
	return nil
}

func (s *gaoFullPackedFactorStore) ReadFactor(index int) (ltcommon.LinearTransformation, error) {
	if err := s.loadResidentFactor(index); err != nil {
		return ltcommon.LinearTransformation{}, err
	}
	return s.resident[index], nil
}

// ReadValidatedFactor implements dft.ValidatedFactorSource. The first call for
// an index loads and validates the disk frame; subsequent calls are resident
// lookups and perform no filesystem operation or full factor validation.
func (s *gaoFullPackedFactorStore) ReadValidatedFactor(index int) (dft.ValidatedFactor, error) {
	if err := s.loadResidentFactor(index); err != nil {
		return dft.ValidatedFactor{}, err
	}
	return s.validated[index], nil
}

func (s *gaoFullPackedFactorStore) loadResidentFactor(index int) error {
	if s == nil || s.closed {
		return fmt.Errorf("secureeval: Gao DFT factor store is nil or closed")
	}
	if index < 0 || index >= s.factorCount {
		return fmt.Errorf("secureeval: Gao DFT factor index %d is out of range", index)
	}
	if s.residentReady[index] {
		return nil
	}
	if index >= len(s.factorPaths) || index >= len(s.factorSizes) {
		return fmt.Errorf("secureeval: Gao DFT factor %d has no backing frame", index)
	}
	info, err := os.Stat(s.factorPaths[index])
	if err != nil {
		return fmt.Errorf("secureeval: stat Gao DFT factor %d: %w", index, err)
	}
	if info.Size() != s.factorSizes[index] {
		return fmt.Errorf(
			"secureeval: Gao DFT factor %d size is %d, want %d", index, info.Size(), s.factorSizes[index],
		)
	}
	factor, err := readGaoFactorFile(s.factorPaths[index], s.params, s.literal, index, s.factorCount)
	if err != nil {
		return err
	}
	validated, err := dft.NewValidatedFactor(s.params, s.literal, index, factor)
	if err != nil {
		return fmt.Errorf("secureeval: validate Gao DFT factor %d: %w", index, err)
	}
	var bytes uint64
	for _, poly := range factor.Vec {
		bytes += uint64(poly.BinarySize())
	}
	s.resident[index] = factor
	s.validated[index] = validated
	s.residentReady[index] = true
	s.diskLoads[index]++
	s.residentBytes += bytes
	return nil
}

// Close removes the evaluator-private temporary factor directory. It is
// idempotent; no factor may be read after the first call.
func (s *gaoFullPackedFactorStore) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	directory := s.directory
	s.directory = ""
	for index := range s.resident {
		s.resident[index] = ltcommon.LinearTransformation{}
		s.validated[index] = dft.ValidatedFactor{}
	}
	s.factorPaths = nil
	s.factorSizes = nil
	s.factorCount = 0
	s.resident = nil
	s.validated = nil
	s.residentReady = nil
	s.diskLoads = nil
	s.residentBytes = 0
	if directory == "" {
		return nil
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("secureeval: remove Gao DFT factor store: %w", err)
	}
	return nil
}

func writeGaoFactorFile(
	path string,
	literal dft.MatrixLiteral,
	index, count int,
	factor ltcommon.LinearTransformation,
) (size int64, err error) {
	if factor.MetaData == nil {
		return 0, fmt.Errorf("secureeval: Gao DFT factor %d metadata is nil", index)
	}
	literalBytes, err := literal.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("secureeval: marshal Gao DFT literal: %w", err)
	}
	metadataBytes, err := factor.MetaData.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("secureeval: marshal Gao DFT factor metadata: %w", err)
	}
	keys := make([]int, 0, len(factor.Vec))
	for key := range factor.Vec {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	polySizes := make([]uint64, len(keys))
	for position, key := range keys {
		polySizes[position] = uint64(factor.Vec[key].BinarySize())
	}
	headerBytes, err := json.Marshal(gaoFactorFileHeader{
		Version: gaoFactorStoreVersion, Index: index, Count: count,
		Literal: literalBytes, MetaData: metadataBytes,
		LogBabyStepGiantStepRatio: factor.LogBabyStepGiantStepRatio,
		N1:                        factor.N1, LevelQ: factor.LevelQ, LevelP: factor.LevelP,
		Keys: keys, PolySizes: polySizes,
	})
	if err != nil {
		return 0, fmt.Errorf("secureeval: marshal Gao DFT factor header: %w", err)
	}
	if len(headerBytes) == 0 || uint64(len(headerBytes)) > gaoFactorStoreHeaderMaxBytes {
		return 0, fmt.Errorf("secureeval: Gao DFT factor header size is invalid")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("secureeval: create Gao DFT factor file: %w", err)
	}
	complete := false
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if !complete || err != nil {
			_ = os.Remove(path)
			size = 0
		}
	}()
	writer := bufio.NewWriterSize(file, gaoFactorStoreBufferBytes)
	if _, err = writer.Write(gaoFactorStoreMagic[:]); err != nil {
		return 0, err
	}
	if err = binary.Write(writer, binary.LittleEndian, uint64(len(headerBytes))); err != nil {
		return 0, err
	}
	if _, err = writer.Write(headerBytes); err != nil {
		return 0, err
	}
	for position, key := range keys {
		if err = binary.Write(writer, binary.LittleEndian, polySizes[position]); err != nil {
			return 0, err
		}
		written, writeErr := factor.Vec[key].WriteTo(writer)
		if writeErr != nil {
			return 0, writeErr
		}
		if uint64(written) != polySizes[position] {
			return 0, fmt.Errorf("secureeval: Gao DFT factor polynomial wrote %d bytes, want %d", written, polySizes[position])
		}
	}
	if err = writer.Flush(); err != nil {
		return 0, err
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	complete = true
	return position, nil
}

func readGaoFactorFile(
	path string,
	params ckks.Parameters,
	literal dft.MatrixLiteral,
	index, count int,
) (ltcommon.LinearTransformation, error) {
	file, err := os.Open(path)
	if err != nil {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: open Gao DFT factor %d: %w", index, err)
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, gaoFactorStoreBufferBytes)
	var magic [8]byte
	if _, err = io.ReadFull(reader, magic[:]); err != nil || magic != gaoFactorStoreMagic {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d has invalid magic", index)
	}
	var headerLength uint64
	if err = binary.Read(reader, binary.LittleEndian, &headerLength); err != nil || headerLength == 0 || headerLength > gaoFactorStoreHeaderMaxBytes {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d has invalid header length", index)
	}
	headerBytes := make([]byte, int(headerLength))
	if _, err = io.ReadFull(reader, headerBytes); err != nil {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: read Gao DFT factor %d header: %w", index, err)
	}
	var header gaoFactorFileHeader
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: decode Gao DFT factor %d header: %w", index, err)
	}
	wantLiteral, err := literal.MarshalBinary()
	if err != nil {
		return ltcommon.LinearTransformation{}, err
	}
	if header.Version != gaoFactorStoreVersion || header.Index != index || header.Count != count ||
		!bytes.Equal(header.Literal, wantLiteral) || len(header.Keys) == 0 ||
		len(header.Keys) != len(header.PolySizes) ||
		header.LevelQ != literal.LevelQ || header.LevelP != literal.LevelP ||
		header.LogBabyStepGiantStepRatio != literal.LogBSGSRatio {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d header identity changed", index)
	}
	if !slices.IsSorted(header.Keys) {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d keys are not sorted", index)
	}
	for position := 1; position < len(header.Keys); position++ {
		if header.Keys[position] == header.Keys[position-1] {
			return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d contains a duplicate key", index)
		}
	}
	var metadata rlwe.MetaData
	if err = metadata.UnmarshalBinary(header.MetaData); err != nil {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: decode Gao DFT factor %d metadata: %w", index, err)
	}
	factor := ltcommon.LinearTransformation{
		MetaData:                  metadata.CopyNew(),
		LogBabyStepGiantStepRatio: header.LogBabyStepGiantStepRatio,
		N1:                        header.N1, LevelQ: header.LevelQ, LevelP: header.LevelP,
		Vec: make(map[int]ringqp.Poly, len(header.Keys)),
	}
	for position, key := range header.Keys {
		var framedSize uint64
		if err = binary.Read(reader, binary.LittleEndian, &framedSize); err != nil || framedSize != header.PolySizes[position] {
			return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d polynomial frame %d is invalid", index, position)
		}
		poly := ringqp.NewPoly(params.N(), header.LevelQ, header.LevelP)
		if framedSize != uint64(poly.BinarySize()) {
			return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d polynomial frame %d size changed", index, position)
		}
		read, readErr := poly.ReadFrom(reader)
		if readErr != nil || uint64(read) != framedSize {
			return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: read Gao DFT factor %d polynomial %d: %w", index, position, readErr)
		}
		factor.Vec[key] = poly
	}
	if _, err = reader.ReadByte(); err != io.EOF {
		return ltcommon.LinearTransformation{}, fmt.Errorf("secureeval: Gao DFT factor %d has trailing payload", index)
	}
	return factor, nil
}

func cloneGaoFullPackedFactorLiteral(literal dft.MatrixLiteral) dft.MatrixLiteral {
	clone := literal
	clone.Levels = append([]int(nil), literal.Levels...)
	if literal.Scaling != nil {
		clone.Scaling = new(big.Float).Copy(literal.Scaling)
	}
	return clone
}
