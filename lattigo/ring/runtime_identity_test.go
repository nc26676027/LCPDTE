package ring

import "testing"

func runtimeIdentityTestRings(t *testing.T) (*Ring, *Ring) {
	t.Helper()
	gen := NewNTTFriendlyPrimesGenerator(30, 32)
	moduli, err := gen.NextUpstreamPrimes(5)
	if err != nil {
		t.Fatal(err)
	}
	ringQ, err := NewRing(16, moduli[:3])
	if err != nil {
		t.Fatal(err)
	}
	ringP, err := NewRing(16, moduli[3:])
	if err != nil {
		t.Fatal(err)
	}
	return ringQ, ringP
}

func TestBasisExtenderRuntimeIdentitySnapshot(t *testing.T) {
	ringQ, ringP := runtimeIdentityTestRings(t)
	be := NewBasisExtender(ringQ, ringP)
	before, err := be.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	inputQ, outputP := ringQ.NewPoly(), ringP.NewPoly()
	for i := range inputQ.Coeffs[0] {
		inputQ.Coeffs[0][i] = uint64(i + 1)
	}
	be.ModUpQtoP(0, 0, inputQ, outputP)
	afterOperation, err := be.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(afterOperation) {
		t.Fatal("scratch content changed the runtime identity")
	}

	foreign := NewBasisExtender(ringQ, ringP)
	*be = *foreign
	afterReplacement, err := be.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterReplacement) {
		t.Fatal("same-parameter whole-value replacement was not detected")
	}

	var nilBE *BasisExtender
	if _, err := nilBE.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil BasisExtender did not fail closed")
	}
}

func TestDecomposerRuntimeIdentitySnapshot(t *testing.T) {
	ringQ, ringP := runtimeIdentityTestRings(t)
	decomposer := NewDecomposer(ringQ, ringP)
	before, err := decomposer.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	foreign := NewDecomposer(ringQ, ringP)
	*decomposer = *foreign
	afterReplacement, err := decomposer.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Equal(afterReplacement) {
		t.Fatal("same-parameter whole-value replacement was not detected")
	}

	var nilDecomposer *Decomposer
	if _, err := nilDecomposer.RuntimeIdentitySnapshot(); err == nil {
		t.Fatal("nil Decomposer did not fail closed")
	}
}
