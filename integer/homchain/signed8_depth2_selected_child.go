package homchain

import (
	"fmt"
	"reflect"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	signed8Depth2SelectedChildProfileSchema = "signed8-depth2-selected-child-profile-v1"
	signed8Depth2SelectedChildInputSchema   = "signed8-depth2-selected-child-input-v1"
	signed8Depth2SelectedChildResultSchema  = "signed8-depth2-selected-child-result-v1"
	signed8Depth2SelectedChildLinkageSchema = "signed8-depth2-selected-child-linkage-v1"
	signed8Depth2SelectedChildTraceSchema   = "signed8-depth2-selected-child-trace-v1"
)

// Signed8Depth2SelectedChildFidelity keeps the bounded functional profile
// distinct from the Route-B security profile and from exact-float32 LCPDTE.
type Signed8Depth2SelectedChildFidelity string

const Signed8Depth2SelectedChildFunctionalNotSecure Signed8Depth2SelectedChildFidelity = "functional_not_secure"

// Signed8Depth2SelectedChildProfile authenticates the complete source-faithful
// public-root/opaque-child depth-2 circuit graph.
type Signed8Depth2SelectedChildProfile struct {
	fidelity                     Signed8Depth2SelectedChildFidelity
	operandMode                  Signed8ComparatorOperandMode
	parameterDigest, rangeDigest string
	treeDigest, scheduleDigest   string
	tree                         treeplan.BinaryTree[int8, float64]
	featureIDs                   [3]int
	rootThreshold                int8
	rootThresholdPayloadDigest   string
	comparatorProfileDigest      string
	selectorProfileDigest        string
	prefixProfileDigest          string
	childProfileDigest           string
	terminalProfileDigest        string
	digest                       string
}

func (p Signed8Depth2SelectedChildProfile) Fidelity() Signed8Depth2SelectedChildFidelity {
	return p.fidelity
}
func (p Signed8Depth2SelectedChildProfile) OperandMode() Signed8ComparatorOperandMode {
	return p.operandMode
}
func (p Signed8Depth2SelectedChildProfile) ParameterDigest() string { return p.parameterDigest }
func (p Signed8Depth2SelectedChildProfile) RangeDigest() string     { return p.rangeDigest }
func (p Signed8Depth2SelectedChildProfile) TreeDigest() string      { return p.treeDigest }
func (p Signed8Depth2SelectedChildProfile) ScheduleDigest() string  { return p.scheduleDigest }
func (p Signed8Depth2SelectedChildProfile) Tree() treeplan.BinaryTree[int8, float64] {
	return cloneSigned8Depth2Tree(p.tree)
}
func (p Signed8Depth2SelectedChildProfile) FeatureIDs() [3]int  { return p.featureIDs }
func (p Signed8Depth2SelectedChildProfile) RootThreshold() int8 { return p.rootThreshold }
func (p Signed8Depth2SelectedChildProfile) RootThresholdPayloadDigest() string {
	return p.rootThresholdPayloadDigest
}
func (p Signed8Depth2SelectedChildProfile) ComparatorProfileDigest() string {
	return p.comparatorProfileDigest
}
func (p Signed8Depth2SelectedChildProfile) SelectorProfileDigest() string {
	return p.selectorProfileDigest
}
func (p Signed8Depth2SelectedChildProfile) PrefixProfileDigest() string {
	return p.prefixProfileDigest
}
func (p Signed8Depth2SelectedChildProfile) ChildProfileDigest() string {
	return p.childProfileDigest
}
func (p Signed8Depth2SelectedChildProfile) TerminalProfileDigest() string {
	return p.terminalProfileDigest
}
func (p Signed8Depth2SelectedChildProfile) Digest() string { return p.digest }

func cloneSigned8Depth2SelectedChildProfile(p Signed8Depth2SelectedChildProfile) Signed8Depth2SelectedChildProfile {
	p.tree = cloneSigned8Depth2Tree(p.tree)
	return p
}

type signed8Depth2SelectedChildCircuitGraph struct {
	circuit                      *Signed8Depth2SelectedChildCircuit
	comparator                   *Signed8ComparatorCircuit
	selector                     *SelectorReraiseDecodeCircuit
	prefix                       *Signed8Depth2SourcePrefixCircuit
	child                        *Signed8Depth2ChildComparatorCircuit
	terminal                     *Signed8Depth2TerminalLeafCircuit
	rootThreshold, thresholdSeal *rlwe.Plaintext
	rootThresholdPayloadDigest   string
	profileDigest                string
}

// Signed8Depth2SelectedChildCircuit owns the only admitted order of the five
// accepted subcircuits. Callers cannot inject intermediate selectors,
// thresholds, child comparisons or leaves.
type Signed8Depth2SelectedChildCircuit struct {
	comparator                 *Signed8ComparatorCircuit
	selector                   *SelectorReraiseDecodeCircuit
	prefix                     *Signed8Depth2SourcePrefixCircuit
	child                      *Signed8Depth2ChildComparatorCircuit
	terminal                   *Signed8Depth2TerminalLeafCircuit
	tree                       treeplan.BinaryTree[int8, float64]
	rootThreshold              *rlwe.Plaintext
	rootThresholdSeal          *rlwe.Plaintext
	rootThresholdPayloadDigest string
	profile                    Signed8Depth2SelectedChildProfile
	graph                      signed8Depth2SelectedChildCircuitGraph
}

// Signed8Depth2SelectedChildInput is an owned three-node projection of a
// feature-indexed input vector. The order is root, left child, right child.
type Signed8Depth2SelectedChildInput struct {
	root, left, right          Signed8FeatureInput
	profileDigest              string
	treeDigest, scheduleDigest string
	featureIDs                 [3]int
	featurePayloadDigests      [3]string
	featureProvenanceDigests   [3]string
	provenanceDigest           string
}

func (i Signed8Depth2SelectedChildInput) FeatureIDs() [3]int { return i.featureIDs }
func (i Signed8Depth2SelectedChildInput) FeaturePayloadDigests() [3]string {
	return i.featurePayloadDigests
}
func (i Signed8Depth2SelectedChildInput) FeatureProvenanceDigests() [3]string {
	return i.featureProvenanceDigests
}
func (i Signed8Depth2SelectedChildInput) ProvenanceDigest() string { return i.provenanceDigest }
func (i Signed8Depth2SelectedChildInput) RootFeatureCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(i.root.ciphertext)
}
func (i Signed8Depth2SelectedChildInput) LeftFeatureCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(i.left.ciphertext)
}
func (i Signed8Depth2SelectedChildInput) RightFeatureCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(i.right.ciphertext)
}

// NewSigned8Depth2SelectedChildCircuit derives the complete graph and every
// model constant from one comparator and one immutable depth-2 tree.
func NewSigned8Depth2SelectedChildCircuit(
	comparator *Signed8ComparatorCircuit,
	tree treeplan.BinaryTree[int8, float64],
) (*Signed8Depth2SelectedChildCircuit, error) {
	if comparator == nil {
		return nil, fmt.Errorf("homchain: nil comparator for depth2 selected-child circuit")
	}
	if err := comparator.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate selected-child comparator: %w", err)
	}
	if tree.Depth != 2 {
		return nil, fmt.Errorf("homchain: selected-child circuit requires depth=2, got %d", tree.Depth)
	}
	if err := tree.Validate(); err != nil {
		return nil, fmt.Errorf("homchain: invalid selected-child tree: %w", err)
	}

	selector, err := NewSelectorReraiseDecodeCircuit(comparator)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selected-child root selector: %w", err)
	}
	prefix, err := NewSigned8Depth2SourcePrefixCircuit(selector, tree)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selected-child source prefix: %w", err)
	}
	child, err := NewSigned8Depth2ChildComparatorCircuit(prefix)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selected-child child comparator: %w", err)
	}
	terminal, err := NewSigned8Depth2TerminalLeafCircuit(child)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selected-child terminal: %w", err)
	}

	ownedTree := cloneSigned8Depth2Tree(tree)
	featureIDs := [3]int{ownedTree.Splits[0].Feature, ownedTree.Splits[1].Feature, ownedTree.Splits[2].Feature}
	rootThreshold := int64(ownedTree.Splits[0].Threshold)
	thresholds := [signed8Words]int64{rootThreshold, rootThreshold, rootThreshold, rootThreshold}
	residues, err := comparator.validatePublicThresholds(thresholds)
	if err != nil {
		return nil, fmt.Errorf("homchain: selected-child root threshold: %w", err)
	}
	rootThresholdPlaintext, err := newSigned8WordPlaintext(
		comparator.params, comparator.refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, residues,
	)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode selected-child root threshold: %w", err)
	}
	rootThresholdPayloadDigest, err := signed8PlaintextDigest(rootThresholdPlaintext)
	if err != nil {
		return nil, err
	}

	prefixProfile := prefix.Profile()
	profile := Signed8Depth2SelectedChildProfile{
		fidelity:        Signed8Depth2SelectedChildFunctionalNotSecure,
		operandMode:     Signed8PublicThresholdCTPT,
		parameterDigest: prefixProfile.ParameterDigest(), rangeDigest: prefixProfile.RangeDigest(),
		treeDigest: prefixProfile.TreeDigest(), scheduleDigest: prefixProfile.ScheduleDigest(),
		tree: cloneSigned8Depth2Tree(ownedTree), featureIDs: featureIDs, rootThreshold: ownedTree.Splits[0].Threshold,
		rootThresholdPayloadDigest: rootThresholdPayloadDigest,
		comparatorProfileDigest:    comparator.PublicProfile().Digest(),
		selectorProfileDigest:      selector.Profile().Digest(), prefixProfileDigest: prefixProfile.Digest(),
		childProfileDigest: child.Profile().Digest(), terminalProfileDigest: terminal.Profile().Digest(),
	}
	profile.digest = digestSigned8Depth2SelectedChildProfile(profile)
	circuit := &Signed8Depth2SelectedChildCircuit{
		comparator: comparator, selector: selector, prefix: prefix, child: child, terminal: terminal,
		tree: ownedTree, rootThreshold: rootThresholdPlaintext, rootThresholdSeal: rootThresholdPlaintext.CopyNew(),
		rootThresholdPayloadDigest: rootThresholdPayloadDigest, profile: profile,
	}
	circuit.graph = signed8Depth2SelectedChildCircuitGraph{
		circuit: circuit, comparator: comparator, selector: selector, prefix: prefix, child: child, terminal: terminal,
		rootThreshold: rootThresholdPlaintext, thresholdSeal: circuit.rootThresholdSeal,
		rootThresholdPayloadDigest: rootThresholdPayloadDigest, profileDigest: profile.digest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *Signed8Depth2SelectedChildCircuit) Profile() Signed8Depth2SelectedChildProfile {
	if c == nil {
		return Signed8Depth2SelectedChildProfile{}
	}
	return cloneSigned8Depth2SelectedChildProfile(c.profile)
}

// BindFeatures selects the exact three node-referenced handles from a
// feature-indexed vector and takes detached ownership of each ciphertext.
func (c *Signed8Depth2SelectedChildCircuit) BindFeatures(
	features []Signed8FeatureInput,
) (Signed8Depth2SelectedChildInput, error) {
	if err := c.validate(); err != nil {
		return Signed8Depth2SelectedChildInput{}, err
	}
	selected := [3]Signed8FeatureInput{}
	for node, featureID := range c.profile.featureIDs {
		if featureID < 0 || featureID >= len(features) {
			return Signed8Depth2SelectedChildInput{}, fmt.Errorf(
				"homchain: selected-child node %d requires feature %d, input has %d features",
				node, featureID, len(features),
			)
		}
		if err := c.comparator.validateFeatureHandle(features[featureID]); err != nil {
			return Signed8Depth2SelectedChildInput{}, fmt.Errorf(
				"homchain: selected-child feature %d for node %d: %w", featureID, node, err,
			)
		}
		selected[node] = cloneSigned8FeatureInput(features[featureID])
	}
	input := Signed8Depth2SelectedChildInput{
		root: selected[0], left: selected[1], right: selected[2],
		profileDigest: c.profile.digest, treeDigest: c.profile.treeDigest,
		scheduleDigest: c.profile.scheduleDigest, featureIDs: c.profile.featureIDs,
		featurePayloadDigests: [3]string{selected[0].payloadDigest, selected[1].payloadDigest, selected[2].payloadDigest},
		featureProvenanceDigests: [3]string{
			selected[0].provenanceDigest, selected[1].provenanceDigest, selected[2].provenanceDigest,
		},
	}
	input.provenanceDigest = digestSigned8Depth2SelectedChildInput(input)
	if err := c.validateInput(input); err != nil {
		return Signed8Depth2SelectedChildInput{}, err
	}
	return input, nil
}

// BindCiphertexts is the raw Lattigo convenience boundary. Only features
// referenced by the exact tree are admitted and copied.
func (c *Signed8Depth2SelectedChildCircuit) BindCiphertexts(
	ciphertexts []*rlwe.Ciphertext,
	declaredSource ckks.Parameters,
) (Signed8Depth2SelectedChildInput, error) {
	if err := c.validate(); err != nil {
		return Signed8Depth2SelectedChildInput{}, err
	}
	features := make([]Signed8FeatureInput, len(ciphertexts))
	bound := make(map[int]bool, len(c.profile.featureIDs))
	for _, featureID := range c.profile.featureIDs {
		if featureID < 0 || featureID >= len(ciphertexts) {
			return Signed8Depth2SelectedChildInput{}, fmt.Errorf(
				"homchain: selected-child requires feature %d, input has %d ciphertexts", featureID, len(ciphertexts),
			)
		}
		if bound[featureID] {
			continue
		}
		feature, err := c.comparator.BindFeature(ciphertexts[featureID], declaredSource)
		if err != nil {
			return Signed8Depth2SelectedChildInput{}, fmt.Errorf("homchain: bind selected-child feature %d: %w", featureID, err)
		}
		features[featureID] = feature
		bound[featureID] = true
	}
	return c.BindFeatures(features)
}

func (c *Signed8Depth2SelectedChildCircuit) validateInput(input Signed8Depth2SelectedChildInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	selected := [3]Signed8FeatureInput{input.root, input.left, input.right}
	for node := range selected {
		if err := c.comparator.validateFeatureHandle(selected[node]); err != nil {
			return fmt.Errorf("homchain: validate selected-child node %d feature: %w", node, err)
		}
		if input.featurePayloadDigests[node] != selected[node].payloadDigest ||
			input.featureProvenanceDigests[node] != selected[node].provenanceDigest {
			return fmt.Errorf("homchain: selected-child node %d feature seal changed", node)
		}
	}
	if input.profileDigest != c.profile.digest || input.treeDigest != c.profile.treeDigest ||
		input.scheduleDigest != c.profile.scheduleDigest || input.featureIDs != c.profile.featureIDs ||
		input.provenanceDigest != digestSigned8Depth2SelectedChildInput(input) {
		return fmt.Errorf("homchain: selected-child input has foreign profile, tree, schedule, feature mapping, or provenance")
	}
	return nil
}

func (c *Signed8Depth2SelectedChildCircuit) validate() error {
	if c == nil || c.comparator == nil || c.selector == nil || c.prefix == nil || c.child == nil ||
		c.terminal == nil || c.rootThreshold == nil || c.rootThresholdSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete selected-child circuit")
	}
	g := c.graph
	if g.circuit != c || g.comparator != c.comparator || g.selector != c.selector || g.prefix != c.prefix ||
		g.child != c.child || g.terminal != c.terminal || g.rootThreshold != c.rootThreshold ||
		g.thresholdSeal != c.rootThresholdSeal || g.rootThresholdPayloadDigest != c.rootThresholdPayloadDigest ||
		g.profileDigest != c.profile.digest {
		return fmt.Errorf("homchain: selected-child circuit object graph changed")
	}
	if err := c.comparator.validate(); err != nil {
		return err
	}
	if err := c.selector.validate(); err != nil {
		return err
	}
	if err := c.prefix.validate(); err != nil {
		return err
	}
	if err := c.child.validate(); err != nil {
		return err
	}
	if err := c.terminal.validate(); err != nil {
		return err
	}
	if c.selector.producer != c.comparator || c.prefix.selector != c.selector ||
		c.child.prefix != c.prefix || c.terminal.child != c.child {
		return fmt.Errorf("homchain: selected-child nested circuit ownership changed")
	}
	if !c.rootThreshold.Equal(c.rootThresholdSeal) {
		return fmt.Errorf("homchain: selected-child root-threshold cache changed")
	}
	rootThresholdDigest, err := signed8PlaintextDigest(c.rootThreshold)
	if err != nil || rootThresholdDigest != c.rootThresholdPayloadDigest {
		return fmt.Errorf("homchain: selected-child root-threshold payload changed: %v", err)
	}
	want := c.profile
	if want.fidelity != Signed8Depth2SelectedChildFunctionalNotSecure ||
		want.operandMode != Signed8PublicThresholdCTPT || want.parameterDigest != c.prefix.profile.parameterDigest ||
		want.rangeDigest != c.prefix.profile.rangeDigest || want.treeDigest != c.prefix.profile.treeDigest ||
		want.scheduleDigest != c.prefix.profile.scheduleDigest || !reflect.DeepEqual(want.tree, c.tree) ||
		want.featureIDs != ([3]int{c.tree.Splits[0].Feature, c.tree.Splits[1].Feature, c.tree.Splits[2].Feature}) ||
		want.rootThreshold != c.tree.Splits[0].Threshold || want.rootThresholdPayloadDigest != rootThresholdDigest ||
		want.comparatorProfileDigest != c.comparator.publicProfile.digest ||
		want.selectorProfileDigest != c.selector.profile.digest || want.prefixProfileDigest != c.prefix.profile.digest ||
		want.childProfileDigest != c.child.profile.digest || want.terminalProfileDigest != c.terminal.profile.digest ||
		want.digest != digestSigned8Depth2SelectedChildProfile(want) {
		return fmt.Errorf("homchain: selected-child profile changed")
	}
	return nil
}

func cloneSigned8FeatureInput(input Signed8FeatureInput) Signed8FeatureInput {
	input.ciphertext = copyA2BRefreshCiphertext(input.ciphertext)
	return input
}

func cloneSigned8Depth2SelectedChildInput(input Signed8Depth2SelectedChildInput) Signed8Depth2SelectedChildInput {
	input.root = cloneSigned8FeatureInput(input.root)
	input.left = cloneSigned8FeatureInput(input.left)
	input.right = cloneSigned8FeatureInput(input.right)
	return input
}

func equalSigned8Depth2SelectedChildInputs(left, right Signed8Depth2SelectedChildInput) bool {
	return left.profileDigest == right.profileDigest && left.treeDigest == right.treeDigest &&
		left.scheduleDigest == right.scheduleDigest && left.featureIDs == right.featureIDs &&
		left.featurePayloadDigests == right.featurePayloadDigests &&
		left.featureProvenanceDigests == right.featureProvenanceDigests &&
		left.provenanceDigest == right.provenanceDigest && equalSigned8FeatureInputs(left.root, right.root) &&
		equalSigned8FeatureInputs(left.left, right.left) && equalSigned8FeatureInputs(left.right, right.right) &&
		left.root.ciphertext != nil && right.root.ciphertext != nil &&
		left.left.ciphertext != nil && right.left.ciphertext != nil && left.right.ciphertext != nil && right.right.ciphertext != nil &&
		left.root.ciphertext.Equal(right.root.ciphertext) && left.left.ciphertext.Equal(right.left.ciphertext) &&
		left.right.ciphertext.Equal(right.right.ciphertext)
}

func equalSigned8FeatureInputs(left, right Signed8FeatureInput) bool {
	return left.role == right.role && left.profileDigest == right.profileDigest && left.rangeDigest == right.rangeDigest &&
		left.sourceParameterDigest == right.sourceParameterDigest && left.payloadDigest == right.payloadDigest &&
		left.provenanceDigest == right.provenanceDigest
}

func digestSigned8Depth2SelectedChildProfile(profile Signed8Depth2SelectedChildProfile) string {
	return digestString(fmt.Sprintf(
		"%s|fidelity=%s|mode=%s|params=%s|range=%s|tree=%s|schedule=%s|features=%d,%d,%d|root-threshold=%d|root-threshold-payload=%s|comparator=%s|selector=%s|prefix=%s|child=%s|terminal=%s",
		signed8Depth2SelectedChildProfileSchema, profile.fidelity, profile.operandMode,
		profile.parameterDigest, profile.rangeDigest, profile.treeDigest, profile.scheduleDigest,
		profile.featureIDs[0], profile.featureIDs[1], profile.featureIDs[2], profile.rootThreshold,
		profile.rootThresholdPayloadDigest, profile.comparatorProfileDigest, profile.selectorProfileDigest,
		profile.prefixProfileDigest, profile.childProfileDigest, profile.terminalProfileDigest,
	))
}

func digestSigned8Depth2SelectedChildInput(input Signed8Depth2SelectedChildInput) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|tree=%s|schedule=%s|features=%d,%d,%d|payloads=%s,%s,%s|provenance=%s,%s,%s",
		signed8Depth2SelectedChildInputSchema, input.profileDigest, input.treeDigest, input.scheduleDigest,
		input.featureIDs[0], input.featureIDs[1], input.featureIDs[2],
		input.featurePayloadDigests[0], input.featurePayloadDigests[1], input.featurePayloadDigests[2],
		input.featureProvenanceDigests[0], input.featureProvenanceDigests[1], input.featureProvenanceDigests[2],
	))
}

// BindEvaluator is implemented in signed8_depth2_selected_child_evaluator.go.
func (c *Signed8Depth2SelectedChildCircuit) BindEvaluator(
	source *bootstrapping.Evaluator,
) (*Signed8Depth2SelectedChildEvaluator, error) {
	return c.bindSelectedChildEvaluator(source)
}
