package pcadelegate

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/acmpca"
)

type MockACMClientFactory struct{}

func (f *MockACMClientFactory) newClient() (ACMPCAClient, error) {
	dummyClient := acmpca.ACMPCA{
		Client: nil,
	}
	return &dummyClient, nil
}

func TestBasics(t *testing.T) {

}
