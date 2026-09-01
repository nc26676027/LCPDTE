package homchain

import (
	"fmt"

	"github.com/nc26676027/LCPDTE/integer/z2n"
)

// NewSpecificationsFromRing obtains the closed-form U/V matrices and the
// root-slot encodings of tau/tau^{-1} from the audited z2n plaintext layer.
func NewSpecificationsFromRing(ringZ *z2n.Ring, words int) (Specifications, error) {
	if ringZ == nil {
		return Specifications{}, fmt.Errorf("homchain: nil z2n ring")
	}
	matrices, err := NewMatrixSet(ringZ.Vandermonde(), ringZ.VandermondeInverse())
	if err != nil {
		return Specifications{}, err
	}
	tSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: transform tau to root slots: %w", err)
	}
	tInvSlots, err := ringZ.ToRootSlots(ringZ.TauInverse())
	if err != nil {
		return Specifications{}, fmt.Errorf("homchain: transform tau inverse to root slots: %w", err)
	}
	return NewSpecifications(matrices, words, tSlots, tInvSlots)
}
