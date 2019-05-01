package pcadelegate

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/request"
	log "github.com/sirupsen/logrus"
)

type (
	ACMPCARetryer interface {
		MaxRetries() int
		RetryRules(r *request.Request) time.Duration
		ShouldRetry(r *request.Request) bool
	}

	ACMPCARetry struct {
		client.DefaultRetryer
	}
)

func NewACMPCARetry(maxRetries int) ACMPCARetry {
	retry := ACMPCARetry{
		client.DefaultRetryer{
			NumMaxRetries: maxRetries,
		},
	}
	return retry
}

/*
func (a ACMPCARetry) MaxRetries() int {
	return 3
}
*/
/*
func (a ACMPCARetry) RetryRules(r *request.Request) time.Duration {
	return time.Hour
}
*/

func (a ACMPCARetry) ShouldRetry(r *request.Request) bool {
	log.Infof("There was an error with status code %v with status %v\n", r.HTTPResponse.StatusCode, r.HTTPResponse.Status)
	// Error codes https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_IssueCertificate.html
	return 400 == r.HTTPResponse.StatusCode || a.DefaultRetryer.ShouldRetry(r)
}
