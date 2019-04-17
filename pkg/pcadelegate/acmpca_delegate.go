package pcadelegate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
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
	caARN := string("arn:aws:acm-pca:us-west-2:536616252769:certificate-authority/8b308bd8-f508-416e-9775-5b31f195e21a")
	return NewCADelegate(region, caARN)
}

func NewCADelegate(region, caARN string) (*ACMPCADelegate, error) {
	session, sessionErr := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	//config := aws.NewConfig().WithLogLevel(aws.LogDebugWithRequestErrors)
	config := aws.NewConfig()

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
func (c ACMPCADelegate) IssueEndEntityCrt(csr *x509.CertificateRequest) (tls.Crt, error) {
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
	log.Errorf("Successfully got certficate combo: %v", *certificateOutput.Certificate)

	// parse the cert
	endCert, extractEndCertError := ExtractEndCertificate(*certificateOutput.Certificate)
	if extractEndCertError != nil {
		return tls.Crt{}, extractEndCertError
	}
	//log.Errorf("Successfully parsed the end certficate %v", endCert)

	trustChain, chopped, extractTrustError := ExtractTrustChain(*certificateOutput.CertificateChain)
	if extractTrustError != nil {
		return tls.Crt{}, extractTrustError
	}

	for i := 0; i < len(trustChain); i++ {
		//log.Errorf("Successfully extracted the trust chain certficate \n%v\n", trustChain[i].Raw)
	}

	crt := tls.Crt{
		Certificate: endCert,
		TrustChain:  trustChain,
	}
	//log.Errorf("Successfully build the tls.Crt certficate %v", crt)

	refroots := x509.NewCertPool()
	refinterm := x509.NewCertPool()

	const refrootCert = "-----BEGIN CERTIFICATE-----\nMIIDxjCCAq6gAwIBAgIJAO6DSG+Jvt0vMA0GCSqGSIb3DQEBDAUAMHAxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEOMAwGA1UECgwF\nVE1FU0gxDjAMBgNVBAsMBVRNRVNIMSIwIAYJKoZIhvcNAQkBFhNUTUVTSEBub3Jk\nc3Ryb20uY29tMB4XDTE5MDMyODIxMTM0MFoXDTE5MDQyNzIxMTM0MFowcDELMAkG\nA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ4wDAYDVQQK\nDAVUTUVTSDEOMAwGA1UECwwFVE1FU0gxIjAgBgkqhkiG9w0BCQEWE1RNRVNIQG5v\ncmRzdHJvbS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeP6ez\n6jFDvmiK54pHhdH9/vwgteQ2SaPCCzH3+LPftE+98r9cYH7q+/AoHHaDUlK3CBRz\n63QrbKFNJfwY5LbEDKma+YR2zSMJLveDlW89hnuwVoCjdfThNqZOoqVOx1QFYBBv\nZ6lvtce2Oc5tmRwOfXudJTragqkMJme0Mn6CCy98R3VGysh7jnPJjb0JD2PygMMx\nKhGuzoM7Ib2Vf6vzOt4oqHFoHkCo1sgLvi7ojCo11ynB0pvequ6HElxgqEnoBUA7\npIhsqe4/gJyC62xjBKON48G/7Ut0xgXMmN0Ir+7nfBiGC8iBVy6smSv+qQ3dAxGx\nUbAUwTKNge9p+1Y3AgMBAAGjYzBhMB0GA1UdDgQWBBSYj5Tn7VrJSXj02YbqGnUv\nypxCGjAfBgNVHSMEGDAWgBSYj5Tn7VrJSXj02YbqGnUvypxCGjAPBgNVHRMBAf8E\nBTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQwFAAOCAQEAcwQf730e\n6OhPRJ7yU5WVfARck3OgG1kWz4O3F0ZT9SC+85Q920jS3oBfaV2G4cTAsLgvk0rM\n62ghhN7BL/a06+iRkD7xO7w9ftcOReUqlaJ2SQi1L3eL6Cn6pu3mHwWyh3DqYdkW\n2y9SYGTWpmkIW/tG2k+/atnHeC7iEfxlO7Xq1aoAVBGJStR9JFQlETn52nRaG03r\ntMyEU+MrZhJDQR9gIFL/lBC/uLAkkNYqN7E4tbzc4n1rr1OuiTq3XeSdSGrxHkcp\nizHKiX1uPiG0iv5fI43XyTwHHlrfesYhxmFOv/I0HdsuFjQUHyPEq9pB0GsqKsoj\nL/EIQ1Caao5a3g==\n-----END CERTIFICATE-----"
	const refintermediateCert = "-----BEGIN CERTIFICATE-----\nMIIDeDCCAmCgAwIBAgICEAkwDQYJKoZIhvcNAQELBQAwcDELMAkGA1UEBhMCVVMx\nCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ4wDAYDVQQKDAVUTUVTSDEO\nMAwGA1UECwwFVE1FU0gxIjAgBgkqhkiG9w0BCQEWE1RNRVNIQG5vcmRzdHJvbS5j\nb20wHhcNMTkwNDEwMjAyMzIyWhcNMjAwNDA5MjAyMzIyWjBLMRcwFQYDVQQKDA5Q\nQ0FfVEVTVF9UTUVTSDEXMBUGA1UECwwOUENBX1RFU1RfVE1FU0gxFzAVBgNVBAMM\nDlBDQV9URVNUX1RNRVNIMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\np5J0qkEsHWAQwV4G4LCj+qRp2bsYq/O3zq+yaFfF8VJJ5va61vWfRob36/vCosgd\ntTrhUSXtRxNMyu/MYPL2vLV14/clXKhS3blldACYeM6VSpQhHsHsRKNm3EIFTZb5\ne8i9ZPjha2cZ09u3mtD5SymJPyPHbuL0TG7Hh1/5RjyOKM23w/nlDlsSepAsqUSb\nsEpXXx88DtdUpc5AgH4FJOn+ZrC3nSlbS/BJxs01krZaZkcDIs2A2gBlMlNC6Szj\nNLXT/qH3e4GuJ9DsiwRCrQjImQTJOow/15J+iLKEXOW6DkKS08Q35YXI1pKUZfDz\nVO7E/aN48Oo3NaV5frYNaQIDAQABo0EwPzAfBgNVHSMEGDAWgBSYj5Tn7VrJSXj0\n2YbqGnUvypxCGjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIC9DANBgkqhkiG\n9w0BAQsFAAOCAQEAV9mqzO/n04GFPleSvTnS8Y1z4DHryWGhPeUpDLJo5M/heWJq\nuHdHo1kbddNrFt6jYsxroNtSIPf5ToEzk+Jh+RULrm6EFnQlnaZWL9tR/6n+TRyT\nLoT9L06gq3JBwitHDAe0U0jxTOT5RbqDh0/y9RaWeHEkZThAHkDWYcTkLdRIlP8U\n8igu5HeqaPWBi8raStey6v4FFWWcZfrfRXwIUFZGyVfgmnK9XkvPaPpOLm4QIMt1\nnt449NMdzRlrsG7digb7oCOSK7K9B/YO5K7SjMvBKJwtiexmxUNPABu0p7cAwy6K\n0iPy6sY511GT7GV2ubKp5kFbRf6NNjHuEZnARA==\n-----END CERTIFICATE-----"
	const refendCert = "-----BEGIN CERTIFICATE-----\nMIIDpzCCApGgAwIBAgIRAMI86n7ZstxnF9GsvEI6V1owCwYJKoZIhvcNAQENMEsx\nFzAVBgNVBAoMDlBDQV9URVNUX1RNRVNIMRcwFQYDVQQLDA5QQ0FfVEVTVF9UTUVT\nSDEXMBUGA1UEAwwOUENBX1RFU1RfVE1FU0gwHhcNMTkwNDE2MjEyMjUyWhcNMTkw\nNTE2MjIyMjUyWjBRMU8wTQYDVQQDE0ZsaW5rZXJkLWlkZW50aXR5LmxpbmtlcmQu\nc2VydmljZWFjY291bnQuaWRlbnRpdHkubGlua2VyZC5jbHVzdGVyLmxvY2FsMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyeLBKJpnfLvR6L4FVcDkMCnSn4OZzUeY\nKW5WFb+kI97/YICFr2ZLkaGO/0iblwea5VA+HndOhei8yYUr/HgA0qOCAU0wggFJ\nMFEGA1UdEQRKMEiCRmxpbmtlcmQtaWRlbnRpdHkubGlua2VyZC5zZXJ2aWNlYWNj\nb3VudC5pZGVudGl0eS5saW5rZXJkLmNsdXN0ZXIubG9jYWwwCQYDVR0TBAIwADAf\nBgNVHSMEGDAWgBT6eMuyRej+m9GHVrZHtJJcvadSwzAdBgNVHQ4EFgQUYOplA6IK\ntL1T0FkRUqaMxUHXc9wwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUF\nBwMBBggrBgEFBQcDAjB6BgNVHR8EczBxMG+gbaBrhmlodHRwOi8vY2FwaW5vLXRl\nc3QtcHJpdmF0ZS1jYS1jcmwuczMudXMtd2VzdC0yLmFtYXpvbmF3cy5jb20vY3Js\nLzhiMzA4YmQ4LWY1MDgtNDE2ZS05Nzc1LTViMzFmMTk1ZTIxYS5jcmwwCwYJKoZI\nhvcNAQENA4IBAQAIEq8Igp8G+SIfcI444LZRT1PgkxqW5Gdvt1krktuFgDz3xBfc\nAVv1Oi+vS8UWdczbGF8/xUCN2MYj2MNVvEVRQFtWgzAH502dBoewEg9Ki410rm1V\nZaIVOSxOIkRlAmqJSMOSd8uBDKtoCa2A9lRHLjFz2xtVpASuWKYiLNDHfhYEzkop\nJ+ZuoH0kar1GQmR8NedJUekxAX9cBZjm68qsoXt8kqh2zo21VJOmDfwmVYo97fnT\nDm7ubCvvuB6kGV+D4D3G37vm+q2+3C/12/JcwyPv+hctVnn1Ed1k/Ut8CUBwjK6V\nIWrPm8ENW+wZ3uoFBgWx94xNDmGp9upPHmYq\n-----END CERTIFICATE-----\n"

	if refrootCert == chopped[1] {
		log.Error("roots match")
	}

	if refintermediateCert == chopped[0] {
		log.Error("intermediates match")
	}

	//okroot := roots.AppendCertsFromPEM([]byte(chopped[1]))
	refokroot := refroots.AppendCertsFromPEM([]byte(refrootCert))
	if !refokroot {
		log.Error("REFERENCE failed to parse rooty certificate")
	}
	//okinterm := interm.AppendCertsFromPEM([]byte(chopped[0]))
	refokinterm := refinterm.AppendCertsFromPEM([]byte(refintermediateCert))
	if !refokinterm {
		log.Error("REFERENCE failed to parse interm certificate")
	}

	refopts := x509.VerifyOptions{
		//DNSName:       "linkerd-identity.linkerd.serviceaccount.identity.linkerd.cluster.local",
		Roots:         refroots,
		Intermediates: refinterm,
	}

	refblock, _ := pem.Decode([]byte(refendCert))
	if refblock == nil {
		panic("REFERENCE failed to parse certificate PEM")
	}
	refcert, referr := x509.ParseCertificate(refblock.Bytes)
	if referr != nil {
		panic("REFERENCE failed to parse certificate: " + referr.Error())
	}

	if _, refverifyErr := refcert.Verify(refopts); refverifyErr != nil {
		log.Errorf("REFERENCE failed to verify certificate " + refverifyErr.Error())
	}

	return crt, nil
}

func ExtractEndCertificate(endCertificate string) (*x509.Certificate, error) {
	// convert the raw certOutput to a pem decoded block
	byteCertificate := []byte(endCertificate)
	pemBlock, _ := pem.Decode(byteCertificate)
	if pemBlock == nil {
		return &x509.Certificate{}, errors.New("Unable to pemDecode the certificate returned from the aws client")
	}
	// parse the pem decoded block into an x509
	cert, certParseError := x509.ParseCertificate(pemBlock.Bytes)
	if certParseError != nil {
		log.Errorf("Unable to parse certificate: %v", certParseError)
		return &x509.Certificate{}, certParseError
	}

	return cert, nil
}

func ExtractTrustChain(certificateChain string) ([]*x509.Certificate, []string, error) {
	// we normalize the chained PEM certificates because the AWS PrivateCA sends chained PEMS but it does not have a newline between each PEM
	normalizedCertChain := NormalizeChainedPEMCertificates(certificateChain)
	chopped := ChopChainedPEMCertificates(certificateChain)

	// parse the cert chain
	byteTrustChain := []byte(normalizedCertChain)
	var pemTrustBytes []byte
	var tempTrust *pem.Block
	var nextBytes []byte

	// if we received an empty CertChain
	if len(byteTrustChain) == 0 {
		return []*x509.Certificate{}, []string{}, errors.New("Unable to decode CertificateChain from the aws client, empty CertificateChain received")
	}

	// walk through each PEM file and append the results without any newline
	nextBytes = byteTrustChain
	for ok := true; ok; ok = (tempTrust != nil) && len(nextBytes) != 0 {
		tempTrust, nextBytes = pem.Decode(nextBytes)
		if tempTrust != nil {
			tempTrustBytes := tempTrust.Bytes
			pemTrustBytes = append(tempTrustBytes, pemTrustBytes...)
		}
	}

	// if there was a failure marshalling the pems from the cert chain
	if len(nextBytes) != 0 {
		return []*x509.Certificate{}, []string{}, errors.New("Unable to decode CertificateChain from the aws client, could not find pem while decoding")
	}

	// if there was a failure marshalling the pems from the cert chain
	if pemTrustBytes == nil {
		return []*x509.Certificate{}, []string{}, errors.New("Unable to decode CertificateChain from the aws client, could not find pem while decoding")
	}

	// convert the chained certificates into a x509 format
	trustChain, certChainParseError := x509.ParseCertificates(pemTrustBytes)
	if certChainParseError != nil {
		log.Errorf("Unable to parse trust chain certificates received from the aws client: %v", certChainParseError)
		return []*x509.Certificate{}, []string{}, certChainParseError
	}

	return trustChain, chopped, nil
}

func NormalizeChainedPEMCertificates(chainedPEMString string) string {
	const targetString = "-----END CERTIFICATE----------BEGIN CERTIFICATE-----"
	const replacementString = "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----"
	const unlimitedReplace = -1
	return strings.Replace(chainedPEMString, targetString, replacementString, unlimitedReplace)
}

func ChopChainedPEMCertificates(chainedPEMString string) []string {
	const targetString = "-----END CERTIFICATE----------BEGIN CERTIFICATE-----"
	const replacementString = "-----END CERTIFICATE-----_-----BEGIN CERTIFICATE-----"
	const unlimitedReplace = -1
	tokenized := strings.Replace(chainedPEMString, targetString, replacementString, unlimitedReplace)
	stringz := strings.Split(tokenized, "_")
	return stringz
}

func (c ACMPCADelegate) getCertificate(acmClient ACMPCAClient, certificateARN string) (*acmpca.GetCertificateOutput, error) {
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

func (c ACMPCADelegate) issueCertificate(acmClient ACMPCAClient, csr *x509.CertificateRequest) (*string, error) {
	signingAlgo := acmpca.SigningAlgorithmSha512withrsa
	validityPeriodType := acmpca.ValidityPeriodTypeDays
	duration := int64(30)
	validity := acmpca.Validity{
		Type:  &validityPeriodType,
		Value: &duration,
	}

	const certType = "CERTIFICATE REQUEST"
	derBlock := pem.Block{
		Type:  certType,
		Bytes: csr.Raw,
	}

	encodedPem := pem.EncodeToMemory(&derBlock)
	if encodedPem == nil {
		log.Error("Was not able to PEM encode the block based on the input certificate signing request")
		return nil, errors.New("Unable to PEM encode the input Certificate Signing Request")
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
