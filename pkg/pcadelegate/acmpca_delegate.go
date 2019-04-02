package pcadelegate

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
)

type (
	// Interface to vend clients
	IACMPCAClientFactory interface {
		newClient() (ACMPCAClient, error)
	}

	// Implements the IACMPCAClientFactory interface
	ACMPCAClientFactory struct {
		Region string
	}

	// Interface that replicates the aws acmpca.Client
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

	config := aws.NewConfig().WithLogLevel(aws.LogDebugWithRequestErrors)

	if sessionErr != nil {
		log.Error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to create aws session")
		return nil, sessionErr
	}

	return acmpca.New(session, config), nil
}

func EasyNewCADelegate() (*ACMPCADelegate, error) {
	//caARN := string("arn:aws:acm-pca:us-west-2:536616252769:certificate-authority/ba1e0a1b-7057-4ad1-ad35-43188c413755")
	caARN := string("arn:aws:acm-pca:us-west-2:536616252769:certificate-authority/46e8fcd0-d615-42a1-9894-4dc45944d554")
	region := string("us-west-2")
	factory := ACMPCAClientFactory{
		Region: region,
	}
	acmClient, clientCreationErr := factory.newClient()
	if clientCreationErr != nil {
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to create client", clientCreationErr)
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
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to create client", clientCreationErr)
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
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to issue a certificate %s", issueCertError)
		return tls.Crt{}, issueCertError
	}

	log.Errorf("*************** Certificate ARN %s", certificateARN)

	time.Sleep(2 * time.Second)

	certificateOutput, getCertificateErr := c.getCertificate(c.acmClient, *certificateARN)
	if getCertificateErr != nil {
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to get certificate", getCertificateErr)
		return tls.Crt{}, getCertificateErr
	}

	byteCertificate := []byte(*certificateOutput.Certificate)
	cert, certParseError := x509.ParseCertificate(byteCertificate)
	if certParseError != nil {
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to parse certificate", certParseError)
		return tls.Crt{}, certParseError
	}

	byteTrustChain := []byte(*certificateOutput.CertificateChain)
	trustChain, certChainParseError := x509.ParseCertificates(byteTrustChain)
	if certChainParseError != nil {
		log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! unable to parse trust chain certificates", certChainParseError)
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

	derBlock := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}

	encodedPem := pem.EncodeToMemory(&derBlock)
	if encodedPem == nil {
		log.Error("!!!!!!!!!!! was not able to encoded PEM")
	}

	issueCertificateInput := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: &c.caARN,
		Csr:                     encodedPem,
		SigningAlgorithm:        &signingAlgo,
		Validity:                &validity,
	}

	arnForCert, certArnErr := acmClient.IssueCertificate(&issueCertificateInput)
	if certArnErr != nil {
		return nil, certArnErr
	}

	return arnForCert.CertificateArn, nil
}
