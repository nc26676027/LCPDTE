package secureeval

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestGaoFullPackedFactorStoreRoundTripAndClose(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	literal := gaoFactorStoreTestLiteral()
	encoder := ckks.NewEncoder(params)
	want, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, literal, encoder, encoder.Prec())
	if err != nil {
		t.Fatal(err)
	}

	parent := t.TempDir()
	store, err := newGaoFullPackedFactorStore(params, literal, encoder, parent, "test-stc")
	if err != nil {
		t.Fatal(err)
	}
	directory := store.directory
	if filepath.Dir(directory) != parent {
		t.Fatalf("store directory %q is outside parent %q", directory, parent)
	}
	if store.FactorCount() != len(want.Matrices) || !reflect.DeepEqual(store.Literal(), literal) {
		t.Fatalf("store identity changed: count=%d literal=%+v", store.FactorCount(), store.Literal())
	}
	for index := range want.Matrices {
		got, err := store.ReadFactor(index)
		if err != nil {
			t.Fatalf("read factor %d: %v", index, err)
		}
		if !reflect.DeepEqual(got, want.Matrices[index]) {
			t.Fatalf("factor %d changed across disk codec", index)
		}
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("private factor directory still exists after Close: %v", err)
	}
	if _, err := store.ReadFactor(0); err == nil {
		t.Fatal("closed factor store accepted a read")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close should be idempotent: %v", err)
	}
}

func TestGaoFullPackedFactorStoreRejectsTruncatedAndWrongIndex(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	literal := gaoFactorStoreTestLiteral()
	store, err := newGaoFullPackedFactorStore(params, literal, ckks.NewEncoder(params), t.TempDir(), "test-cts")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.ReadFactor(-1); err == nil {
		t.Fatal("negative factor index was accepted")
	}
	if _, err := store.ReadFactor(store.FactorCount()); err == nil {
		t.Fatal("out-of-range factor index was accepted")
	}

	path := store.factorPaths[0]
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFactor(0); err == nil {
		t.Fatal("truncated factor payload was accepted")
	}
}

func TestGaoFullPackedFactorStoreLoadsAndValidatesOnceThenStaysResident(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	store, err := newGaoFullPackedFactorStore(
		params, gaoFactorStoreTestLiteral(), ckks.NewEncoder(params), t.TempDir(), "resident",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.ReadValidatedFactor(0); err != nil {
		t.Fatal(err)
	}
	if store.diskLoads[0] != 1 || store.residentBytes == 0 {
		t.Fatalf("disk loads/resident bytes=%d/%d, want 1/non-zero", store.diskLoads[0], store.residentBytes)
	}
	if err := os.Remove(store.factorPaths[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadValidatedFactor(0); err != nil {
		t.Fatalf("resident reread unexpectedly touched removed backing file: %v", err)
	}
	if store.diskLoads[0] != 1 {
		t.Fatalf("resident reread performed %d disk loads, want 1", store.diskLoads[0])
	}
}

func TestGaoFullPackedFactorStorePrepareResidentLoadsAllAndRemovesBacking(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	store, err := newGaoFullPackedFactorStore(
		params, gaoFactorStoreTestLiteral(), ckks.NewEncoder(params), t.TempDir(), "preload",
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := store.directory
	factorCount := store.FactorCount()
	if err := store.PrepareResident(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("backing directory still exists after PrepareResident: %v", err)
	}
	if store.directory != "" || store.factorPaths != nil || store.factorSizes != nil {
		t.Fatalf("backing references retained after PrepareResident: dir=%q paths=%v sizes=%v", store.directory, store.factorPaths, store.factorSizes)
	}
	if store.FactorCount() != factorCount || store.residentBytes == 0 {
		t.Fatalf("factor count/resident bytes=%d/%d, want %d/non-zero", store.FactorCount(), store.residentBytes, factorCount)
	}
	var wantResidentBytes uint64
	for index := 0; index < factorCount; index++ {
		if !store.residentReady[index] || store.diskLoads[index] != 1 {
			t.Fatalf("factor %d ready/loads=%v/%d, want true/1", index, store.residentReady[index], store.diskLoads[index])
		}
		if _, err := store.ReadValidatedFactor(index); err != nil {
			t.Fatalf("resident factor %d: %v", index, err)
		}
		if store.diskLoads[index] != 1 {
			t.Fatalf("resident factor %d reloaded from disk", index)
		}
		for _, poly := range store.resident[index].Vec {
			wantResidentBytes += uint64(poly.BinarySize())
		}
	}
	if store.residentBytes != wantResidentBytes {
		t.Fatalf("resident bytes=%d, want exact encoded payload %d", store.residentBytes, wantResidentBytes)
	}
	if err := store.PrepareResident(); err != nil {
		t.Fatalf("second PrepareResident should be idempotent: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGaoFullPackedFactorStoreCleansDirectoryOnBuildError(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	parent := t.TempDir()
	store, err := newGaoFullPackedFactorStore(params, gaoFactorStoreTestLiteral(), nil, parent, "failed")
	if err == nil || store != nil {
		t.Fatalf("nil encoder: store=%v err=%v", store, err)
	}
	entries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed build left %d temporary entries", len(entries))
	}
}

func TestGaoFullPackedA2BEvaluatorCloseIsIdempotent(t *testing.T) {
	evaluator := &gaoFullPackedA2BEvaluator{}
	if err := evaluator.Close(); err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Close(); err != nil {
		t.Fatal(err)
	}
	if !evaluator.closed {
		t.Fatal("evaluator was not marked closed")
	}
}

func gaoFactorStoreTestParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{60, 60, 60},
		LogP:            []int{60},
		LogDefaultScale: 43,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func gaoFactorStoreTestLiteral() dft.MatrixLiteral {
	return dft.MatrixLiteral{
		Type: dft.HomomorphicDecode, LogSlots: 3,
		LevelQ: 2, LevelP: 0, Levels: []int{1, 1, 1},
		Format: dft.SplitRealAndImag, LogBSGSRatio: 2,
	}
}
