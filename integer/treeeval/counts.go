package treeeval

// OperationCounts records exact computational operations issued through
// Backend. Metadata-only Kind queries are excluded. Opaque is the
// backend-neutral name for a ciphertext-like value.
type OperationCounts struct {
	PublicConstants             int `json:"public_constants"`
	CTCTMultiplications         int `json:"ct_ct_multiplications"`
	CTPublicMultiplications     int `json:"ct_public_multiplications"`
	PublicPublicMultiplications int `json:"public_public_multiplications"`
	Additions                   int `json:"additions"`
	Subtractions                int `json:"subtractions"`
	Comparisons                 int `json:"comparisons"`
	CTCTComparisons             int `json:"ct_ct_comparisons"`
	CTPublicComparisons         int `json:"ct_public_comparisons"`
	PublicPublicComparisons     int `json:"public_public_comparisons"`
	PeakLiveStates              int `json:"peak_live_states"`
	PeakLivePathStates          int `json:"peak_live_path_states"`
	PeakLiveComparisonStates    int `json:"peak_live_comparison_states"`
	FinalLiveStates             int `json:"final_live_states"`
}

// TotalBackendCalls counts each recorded computational backend call once.
// Metadata-only Kind queries are excluded, and the provenance comparison
// fields are classifications of Comparisons rather than additional calls.
func (c OperationCounts) TotalBackendCalls() int {
	return c.PublicConstants +
		c.CTCTMultiplications +
		c.CTPublicMultiplications +
		c.PublicPublicMultiplications +
		c.Additions +
		c.Subtractions +
		c.Comparisons
}

// Result couples an opaque prediction with its exact logical backend trace.
type Result[V any] struct {
	Value  V               `json:"value"`
	Counts OperationCounts `json:"operation_counts"`
}
