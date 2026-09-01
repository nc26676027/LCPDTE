package secureeval

func routeBInstalledEvaluationKeyBinarySize(installed *RouteBInstalledEvaluator) (uint64, error) {
	if installed == nil || installed.cell == nil || installed.cell.evaluator == nil ||
		installed.cell.evaluator.EvaluationKeys == nil ||
		installed.cell.evaluator.MemEvaluationKeySet == nil ||
		installed.cell.evaluator.EvkDenseToSparse == nil ||
		installed.cell.evaluator.EvkSparseToDense == nil {
		return 0, lineagef("installed Route-B evaluation-key inventory is incomplete for serialized-size measurement")
	}
	keys := installed.cell.evaluator.EvaluationKeys
	bytes := keys.MemEvaluationKeySet.BinarySize() + keys.EvkDenseToSparse.BinarySize() + keys.EvkSparseToDense.BinarySize()
	if bytes <= 0 {
		return 0, lineagef("installed Route-B evaluation-key serialized size is non-positive")
	}
	return uint64(bytes), nil
}

func routeBDFTArtifactEncodedBytes(receipt ArtifactBuildReceipt) (uint64, error) {
	report := receipt.Report()
	bytes := report.Payload.STCEncoded.RecordBytes + report.Payload.CTSEncoded.RecordBytes
	if bytes == 0 || bytes < report.Payload.STCEncoded.RecordBytes {
		return 0, lineagef("Route-B encoded DFT artifact serialized size is invalid")
	}
	return bytes, nil
}

func validateRouteBSerializedSizeEvidence(
	inputCiphertextBytes, outputCiphertextBytes, evaluationKeyBytes, dftArtifactBytes uint64,
	receipt RBDFTBuildReceiptReport,
) error {
	allZero := inputCiphertextBytes == 0 && outputCiphertextBytes == 0 && evaluationKeyBytes == 0 && dftArtifactBytes == 0
	if allZero {
		return nil // Accepted pre-size-ledger artifacts remain replayable.
	}
	if inputCiphertextBytes == 0 || outputCiphertextBytes == 0 || evaluationKeyBytes == 0 || dftArtifactBytes == 0 {
		return lineagef("Route-B serialized-size evidence is partial")
	}
	wantDFT := receipt.Payload.STCEncoded.RecordBytes + receipt.Payload.CTSEncoded.RecordBytes
	if wantDFT < receipt.Payload.STCEncoded.RecordBytes || dftArtifactBytes != wantDFT {
		return lineagef("Route-B encoded DFT artifact serialized-size evidence changed")
	}
	return nil
}
