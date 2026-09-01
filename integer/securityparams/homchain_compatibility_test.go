package securityparams_test

import (
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/securityparams"
)

func TestFunctionalManifestParametersMatchAcceptedA2BChain(t *testing.T) {
	manifestParameters, err := securityparams.FunctionalA2BN8Parameters()
	if err != nil {
		t.Fatal(err)
	}
	acceptedParameters, err := homchain.GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	if !manifestParameters.Equal(&acceptedParameters) {
		t.Fatal("functional security manifest parameters differ from the accepted A2B chain")
	}
}
