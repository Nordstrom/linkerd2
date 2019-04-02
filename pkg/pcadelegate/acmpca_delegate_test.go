package pcadelegate

import (
	"errors"
	"testing"

	"github.com/linkerd/linkerd2/pkg/pcadelegate/test_helpers"
)

func TestFailedIssueCert(t *testing.T) {
	expectedError := errors.New("issueCertError")
	myClient := test_helpers.MockACMClient{
		IssueCertError: expectedError,
	}

	subject := ACMPCADelegate{
		acmClient: myClient,
		caARN:     "myARN",
	}

	realCsr := test_helpers.CreateCSR()
	_, err := subject.IssueEndEntityCrt(&realCsr)

	if err != expectedError {
		t.Fail()
	}
}
