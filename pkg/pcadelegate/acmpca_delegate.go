package tls

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/linkerd/linkerd2/pkg/tls"
)

type (
	IACMPCAClientFactory interface {
		newClient() (ACMPCAClient, error)
	}

	ACMPCAClientFactory struct {
		Region string
	}

	ACMPCAClient interface {
		GetCertificate(input *acmpca.GetCertificateInput) (*acmpca.GetCertificateOutput, error)
		IssueCertificate(input *acmpca.IssueCertificateInput) (*acmpca.IssueCertificateOutput, error)
	}

	// Implements the Issuer Interface
	ACMPCADelegate struct {
		acmClient ACMPCAClient
		caARN     string
	}
)

func (f *ACMPCAClientFactory) newClient() (ACMPCAClient, error) {
	// aws session
	session, sessionErr := session.NewSession(&aws.Config{
		Region: aws.String(f.Region),
	})

	if sessionErr != nil {
		return nil, sessionErr
	}

	return acmpca.New(session), nil
}

func EasyNewCADelegate() (*ACMPCADelegate, error) {
	caARN := string("arn:aws:acm-pca:us-west-2:536616252769:certificate-authority/ba1e0a1b-7057-4ad1-ad35-43188c413755")
	region := string("us-west-2")
	factory := ACMPCAClientFactory{
		Region: region,
	}
	acmClient, clientCreationErr := factory.newClient()
	if clientCreationErr != nil {
		return nil, clientCreationErr
	}

	return &ACMPCADelegate{
		acmClient: acmClient,
		caARN:     caARN,
	}, nil
}

func NewCADelegate(clientFactory IACMPCAClientFactory, caARN string) (*ACMPCADelegate, error) {
	acmClient, clientCreationErr := clientFactory.newClient()
	if clientCreationErr != nil {
		return nil, clientCreationErr
	}
	return &ACMPCADelegate{
		acmClient: acmClient,
		caARN:     caARN,
	}, nil
}

// Implements the Issuer Interface
func (c *ACMPCADelegate) IssueEndEntityCrt(csr *x509.CertificateRequest) (tls.Crt, error) {
	certificateARN, issueCertError := c.issueCertificate(c.acmClient, csr)
	if issueCertError != nil {
		return tls.Crt{}, issueCertError
	}

	certificateOutput, getCertificateErr := c.getCertificate(c.acmClient, *certificateARN)
	if getCertificateErr != nil {
		return tls.Crt{}, getCertificateErr
	}

	byteCertificate := []byte(*certificateOutput.Certificate)
	cert, certParseError := x509.ParseCertificate(byteCertificate)
	if certParseError != nil {
		return tls.Crt{}, certParseError
	}

	byteTrustChain := []byte(*certificateOutput.CertificateChain)
	trustChain, certChainParseError := x509.ParseCertificates(byteTrustChain)
	if certChainParseError != nil {
		return tls.Crt{}, certChainParseError
	}

	crt := tls.Crt{
		Certificate: cert,
		TrustChain:  trustChain,
	}

	return crt, nil
}

func (c *ACMPCADelegate) getCertificate(acmClient ACMPCAClient, certificateARN string) (*acmpca.GetCertificateOutput, error) {
	getCertificateInput := acmpca.GetCertificateInput{
		CertificateArn:          &certificateARN,
		CertificateAuthorityArn: &c.caARN,
	}

	getCertOutput, getCertError := acmClient.GetCertificate(&getCertificateInput)
	if getCertError != nil {
		return nil, getCertError
	}
	return getCertOutput, nil
}

func (c *ACMPCADelegate) issueCertificate(acmClient ACMPCAClient, csr *x509.CertificateRequest) (*string, error) {
	signingAlgo := acmpca.SigningAlgorithmSha512withrsa
	validityPeriodType := acmpca.ValidityPeriodTypeDays
	duration := int64(30)
	validity := acmpca.Validity{
		Type:  &validityPeriodType,
		Value: &duration,
	}

	issueCertificateInput := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: &c.caARN,
		Csr:                     csr.Raw,
		SigningAlgorithm:        &signingAlgo,
		Validity:                &validity,
	}

	arnForCert, certArnErr := acmClient.IssueCertificate(&issueCertificateInput)
	if certArnErr != nil {
		return nil, certArnErr
	}

	return arnForCert.CertificateArn, nil
}

func (c *ACMPCADelegate) getCSR() ([]byte, error) {
	pwd, _ := os.Getwd()
	csr, err := ioutil.ReadFile(pwd + "/helper/test_cert_.csr")
	if err != nil {
		return nil, err
	}

	fmt.Println(csr)
	return csr, nil
}
