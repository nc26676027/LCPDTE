package securityparams

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	"github.com/tuneinsight/lattigo/v6/ring"
)

func TestGaoCompatibleN16ParametersAndManifest(t *testing.T) {
	first, err := GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(&second) {
		t.Fatal("deterministic parameter construction drifted")
	}
	if first.LogN() != 16 || first.N() != 1<<16 || first.MaxSlots() != 1<<15 ||
		first.MaxLevel() != 20 || first.MaxLevelP() != 6 || first.LogDefaultScale() != 43 {
		t.Fatalf("unexpected parameter dimensions: LogN=%d N=%d slots=%d LQ=%d LP=%d scale=%d",
			first.LogN(), first.N(), first.MaxSlots(), first.MaxLevel(), first.MaxLevelP(), first.LogDefaultScale())
	}
	if got, ok := first.Xs().(ring.Ternary); !ok || got.H != GaoCompatibleMainWeight || got.P != 0 {
		t.Fatalf("unexpected main secret: %#v", first.Xs())
	}
	if got, ok := first.Xe().(ring.DiscreteGaussian); !ok || got.Sigma != GaoCompatibleSigma || got.Bound != GaoCompatibleBound {
		t.Fatalf("unexpected error distribution: %#v", first.Xe())
	}

	assertPrimeChain(t, first.Q(), 43, first.N())
	assertPrimeChain(t, first.P(), 50, first.N())

	manifest, err := GaoCompatibleN16Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.EstimatorEligible || len(manifest.MissingEvidence) == 0 || manifest.Status != "PENDING-IMPLEMENTATION/PENDING-ESTIMATOR" {
		t.Fatalf("manifest maturity was over-promoted: %#v", manifest)
	}
	if manifest.QProduct.BitLen != first.QBigInt().BitLen() ||
		manifest.PProduct.BitLen != first.PBigInt().BitLen() ||
		manifest.QPProduct.BitLen != first.QPBigInt().BitLen() {
		t.Fatal("manifest product bit lengths differ from live parameters")
	}
	if manifest.QProduct.BitLen != 904 || manifest.PProduct.BitLen != 351 || manifest.QPProduct.BitLen != 1254 {
		t.Fatalf("frozen aggregate bit lengths drifted: Q=%d P=%d QP=%d", manifest.QProduct.BitLen, manifest.PProduct.BitLen, manifest.QPProduct.BitLen)
	}
	if manifest.CanonicalJSONSHA256 != GaoCompatibleManifestDigest {
		t.Fatalf("manifest digest drifted: got %s, want %s", manifest.CanonicalJSONSHA256, GaoCompatibleManifestDigest)
	}
	assertProductRecord(t, manifest.QProduct, first.QBigInt())
	assertProductRecord(t, manifest.PProduct, first.PBigInt())
	assertProductRecord(t, manifest.QPProduct, first.QPBigInt())

	encoded, err := CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ParameterManifest
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CanonicalJSONSHA256 != manifest.CanonicalJSONSHA256 || decoded.TupleID != GaoCompatibleTupleID {
		t.Fatal("canonical JSON round trip changed authenticated fields")
	}
	encodedAgain, err := CanonicalJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(encodedAgain) {
		t.Fatal("canonical JSON is not deterministic")
	}
}

func TestCanonicalJSONRejectsTampering(t *testing.T) {
	manifest, err := GaoCompatibleN16Manifest()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Q[0].Decimal = "1"
	if _, err = CanonicalJSON(manifest); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
}

func TestFunctionalA2BN8ManifestIsExplicitlyInsecure(t *testing.T) {
	params, err := FunctionalA2BN8Parameters()
	if err != nil {
		t.Fatal(err)
	}
	if params.LogN() != 5 || params.MaxLevel() != 20 || params.MaxLevelP() != 0 || params.LogDefaultScale() != 35 {
		t.Fatalf("functional parameter profile drifted: LogN=%d LQ=%d LP=%d scale=%d", params.LogN(), params.MaxLevel(), params.MaxLevelP(), params.LogDefaultScale())
	}
	if got, ok := params.Xs().(ring.Ternary); !ok || got.P != 2/3.0 || got.H != 0 {
		t.Fatalf("functional default secret drifted: %#v", params.Xs())
	}
	manifest, err := FunctionalA2BN8Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "FUNCTIONAL-NOT-SECURE" || manifest.EstimatorEligible || manifest.LogN != 5 || len(manifest.MissingEvidence) == 0 {
		t.Fatalf("functional manifest was over-promoted: %#v", manifest)
	}
	if manifest.QProduct.BitLen != 750 || manifest.PProduct.BitLen != 51 || manifest.QPProduct.BitLen != 800 ||
		manifest.CanonicalJSONSHA256 != FunctionalA2BManifestDigest {
		t.Fatalf("functional manifest evidence drifted: Q=%d P=%d QP=%d digest=%s", manifest.QProduct.BitLen, manifest.PProduct.BitLen, manifest.QPProduct.BitLen, manifest.CanonicalJSONSHA256)
	}
	first, err := CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := FunctionalA2BN8Manifest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalJSON(secondManifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("functional manifest is not deterministic")
	}
}

func assertPrimeChain(t *testing.T, primes []uint64, bitLen, n int) {
	t.Helper()
	if len(primes) == 0 {
		t.Fatal("empty prime chain")
	}
	seen := make(map[uint64]struct{}, len(primes))
	modulus := uint64(2 * n)
	for index, prime := range primes {
		if _, exists := seen[prime]; exists {
			t.Fatalf("duplicate prime at %d: %d", index, prime)
		}
		seen[prime] = struct{}{}
		// Lattigo's deterministic alternating generator is centered at 2^bitLen;
		// upstream primes can therefore lie immediately below or above it.
		gotBitLen := new(big.Int).SetUint64(prime).BitLen()
		if gotBitLen != bitLen && gotBitLen != bitLen+1 {
			t.Fatalf("prime %d has bit length %d, want generator target %d (+0/+1)", index, gotBitLen, bitLen)
		}
		if (prime-1)%modulus != 0 {
			t.Fatalf("prime %d is not 1 mod 2N", index)
		}
		if !new(big.Int).SetUint64(prime).ProbablyPrime(32) {
			t.Fatalf("prime %d failed independent probable-prime check", index)
		}
	}
}

func assertProductRecord(t *testing.T, record ProductRecord, want *big.Int) {
	t.Helper()
	if record.Decimal != want.String() || record.Hex != "0x"+want.Text(16) || record.BitLen != want.BitLen() {
		t.Fatalf("product record mismatch: got=%#v want=%s", record, want)
	}
	digest := sha256.Sum256([]byte(record.Decimal))
	if record.SHA256ASCII != hex.EncodeToString(digest[:]) {
		t.Fatal("product digest mismatch")
	}
	if parsed, ok := new(big.Int).SetString(record.Decimal, 10); !ok || parsed.Cmp(want) != 0 {
		t.Fatalf("decimal product is not canonical: %s", strconv.Quote(record.Decimal))
	}
}
