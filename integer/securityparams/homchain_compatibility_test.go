package securityparams_test

import (
	"testing"

	"dt_go/integer/homchain"
	"dt_go/integer/securityparams"
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
