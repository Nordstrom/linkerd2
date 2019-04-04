package pcadelegate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
)

type (
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

func EasyNewCADelegate() (*ACMPCADelegate, error) {
	region := string("us-west-2")
	caARN := string("arn:aws:acm-pca:us-west-2:536616252769:certificate-authority/46e8fcd0-d615-42a1-9894-4dc45944d554")
	return NewCADelegate(region, caARN)
}

func NewCADelegate(region, caARN string) (*ACMPCADelegate, error) {
	session, sessionErr := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	config := aws.NewConfig().WithLogLevel(aws.LogDebugWithRequestErrors)

	if sessionErr != nil {
		log.Error("Unable to create aws session for AWS ACMPCA")
		return nil, sessionErr
	}

	acmClient := acmpca.New(session, config)

	return &ACMPCADelegate{
		acmClient: acmClient,
		caARN:     caARN,
	}, nil
}

// Implements the Issuer Interface
func (c *ACMPCADelegate) IssueEndEntityCrt(csr *x509.CertificateRequest) (tls.Crt, error) {

	// ask aws client to create a certificate on our behalf, the return value is the arn of the certificate
	certificateARN, issueCertError := c.issueCertificate(c.acmClient, csr)
	if issueCertError != nil {
		log.Errorf("Unable to issue a certificate on the aws client: %v", issueCertError)
		return tls.Crt{}, issueCertError
	}

	time.Sleep(2 * time.Second)

	// ask aws client to fetch the certificate based on the arn
	certificateOutput, getCertificateErr := c.getCertificate(c.acmClient, *certificateARN)
	if getCertificateErr != nil {
		log.Errorf("Unable to execute get certificate on the aws client: %v", getCertificateErr)
		return tls.Crt{}, getCertificateErr
	}

	// parse the cert
	// convert the raw certOutput to a pem decoded block
	byteCertificate := []byte(*certificateOutput.Certificate)
	pemBlock, _ := pem.Decode(byteCertificate)
	if pemBlock == nil {
		return tls.Crt{}, errors.New("Unable to pemDecode the certificate returned from the aws client")
	}
	// parse the pem decoded block into an x509
	cert, certParseError := x509.ParseCertificate(pemBlock.Bytes)
	if certParseError != nil {
		log.Errorf("Unable to parse certificate: %v", certParseError)
		return tls.Crt{}, certParseError
	}

	// parse the cert chain
	byteTrustChain := []byte(*certificateOutput.CertificateChain)
	var pemTrustBytes []byte
	var tempTrust *pem.Block
	var nextBytes []byte

	// if we received an empty CertChain
	if len(byteTrustChain) == 0 {
		return tls.Crt{}, errors.New("Unable to decode CertificateChain from the aws client, empty CertificateChain received")
	}

	for ok := true; ok; ok = (tempTrust != nil) || len(nextBytes) == 0 {
		tempTrust, nextBytes = pem.Decode(byteTrustChain)
		if tempTrust != nil {
			tempTrustBytes := tempTrust.Bytes
			pemTrustBytes = append(pemTrustBytes, tempTrustBytes...)
		}
	}

	// if there was a failure marshalling the pems from the cert chain
	if len(nextBytes) != 0 {
		return tls.Crt{}, errors.New("Unable to decode CertificateChain from the aws client, could not find pem while decoding")
	}

	trustChain, certChainParseError := x509.ParseCertificates(pemTrustBytes)
	if certChainParseError != nil {
		log.Errorf("Unable to parse trust chain certificates received from the aws client: %v", certChainParseError)
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
