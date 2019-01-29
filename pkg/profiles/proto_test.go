package profiles

import (
	"strings"
	"testing"

	"github.com/emicklei/proto"
	sp "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProtoToServiceProfile(t *testing.T) {
	namespace := "myns"
	name := "mysvc"
	controlPlaneNamespace := "linkerd"

	protobuf := `syntax = "proto3";

package emojivoto.v1;

message VoteRequest {
}

message VotingResult {
    string Shortcode = 1;
    int32 Votes = 2;
}

service VotingService {
	rpc VotePoop (VoteRequest) returns (VoteResponse);
}`

	parser := proto.NewParser(strings.NewReader(protobuf))

	expectedServiceProfile := sp.ServiceProfile{
		TypeMeta: ServiceProfileMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "." + namespace + ".svc.cluster.local",
			Namespace: controlPlaneNamespace,
		},
		Spec: sp.ServiceProfileSpec{
			Routes: []*sp.RouteSpec{
				&sp.RouteSpec{
					Name: "VotePoop",
					Condition: &sp.RequestMatch{
						PathRegex: `/emojivoto\.v1\.VotingService/VotePoop`,
						Method:    "POST",
					},
				},
			},
		},
	}

	actualServiceProfile, err := protoToServiceProfile(parser, namespace, name, controlPlaneNamespace)
	if err != nil {
		t.Fatalf("Failed to create ServiceProfile: %v", err)
	}

	err = ServiceProfileYamlEquals(*actualServiceProfile, expectedServiceProfile)
	if err != nil {
		t.Fatalf("ServiceProfiles are not equal: %v", err)
	}
}
