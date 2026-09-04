package homchain_test

import (
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestGaoA2BKernelOutputsComposeDirectlyIntoSameChainB2A(t *testing.T) {
	params, err := homchain.GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	kernel, err := homchain.NewGaoA2BKernelCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	b2a, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 5)
	if err != nil {
		t.Fatal(err)
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	galoisElements := append([]uint64(nil), b2a.Profile().RequiredGaloisElements()...)
	galoisElements = append(galoisElements, kernel.Profile().KeyProfile().ConjugationGaloisElement())
	galoisKeys := keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, galoisKeys...)
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	boundKernel, err := kernel.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	boundB2A, err := b2a.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	words := []uint64{0x00, 0x10, 0xa5, 0xff}
	lowInput := encryptGaoKernelCodes(t, params, encoder, secretKey, words, 0)
	highInput := encryptGaoKernelCodes(t, params, encoder, secretKey, words, 4)
	lowBefore, highBefore := lowInput.CopyNew(), highInput.CopyNew()
	lowResult, err := boundKernel.EvaluateNew(lowInput)
	if err != nil {
		t.Fatal(err)
	}
	highResult, err := boundKernel.EvaluateNew(highInput)
	if err != nil {
		t.Fatal(err)
	}
	if !lowInput.Equal(lowBefore) || !highInput.Equal(highBefore) {
		t.Fatal("Gao kernels mutated a normalized input")
	}
	lowBits := lowResult.MSBCiphertext()
	highBits := highResult.MSBCiphertext()
	if lowBits.Level() != 5 || highBits.Level() != 5 || !lowBits.Scale.Equal(highBits.Scale) {
		t.Fatalf("kernel Boolean halves have incompatible state: low=L%d/%v high=L%d/%v", lowBits.Level(), lowBits.Scale, highBits.Level(), highBits.Scale)
	}
	if !lowBits.Scale.Equal(params.DefaultScale()) || !highBits.Scale.Equal(params.DefaultScale()) ||
		!kernel.Profile().BooleanOutputScale().EqualScale(params.DefaultScale()) ||
		kernel.Profile().BooleanOutputLevel() != 5 {
		t.Fatalf("kernel Boolean output is not sealed as exact L5/S35: profile=L%d/%s low=%v high=%v",
			kernel.Profile().BooleanOutputLevel(), kernel.Profile().BooleanOutputScale().ValueHex(), lowBits.Scale, highBits.Scale)
	}

	lowHandle, err := b2a.BindLow(lowBits)
	if err != nil {
		t.Fatalf("bind real kernel low half: %v", err)
	}
	highHandle, err := b2a.BindHigh(highBits)
	if err != nil {
		t.Fatalf("bind real kernel high half: %v", err)
	}
	input, err := b2a.BindInput(lowHandle, highHandle)
	if err != nil {
		t.Fatal(err)
	}
	result, err := boundB2A.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	b2aAssertResidues(t, mustWord8Ring(t), b2aDecrypt(t, params, encoder, secretKey, result.Ciphertext()), words)
}

func encryptGaoKernelCodes(
	t *testing.T,
	params ckks.Parameters,
	encoder *ckks.Encoder,
	secretKey *rlwe.SecretKey,
	words []uint64,
	bitOffset int,
) *rlwe.Ciphertext {
	t.Helper()
	values := make([]complex128, params.MaxSlots())
	for wordIndex, word := range words {
		for slot := 0; slot < 4; slot++ {
			var prefix uint64
			for j := 0; j <= slot; j++ {
				bit := word >> uint(bitOffset+slot-j) & 1
				prefix += bit << uint(3-j)
			}
			code := (16 - prefix) & 15
			values[wordIndex*4+slot] = complex(float64(code)/256, 0)
		}
	}
	plaintext := ckks.NewPlaintext(params, 17)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func mustWord8Ring(t *testing.T) *z2n.Ring {
	t.Helper()
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	return ringZ
}
