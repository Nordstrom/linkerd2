package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/golang/protobuf/ptypes"
	idctl "github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/config"
	"github.com/linkerd/linkerd2/pkg/flags"
	"github.com/linkerd/linkerd2/pkg/identity"
	"github.com/linkerd/linkerd2/pkg/k8s"
	consts "github.com/linkerd/linkerd2/pkg/k8s"
	pcadelegate "github.com/linkerd/linkerd2/pkg/pcadelegate"
	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// TODO watch trustAnchorsPath for changes
// TODO watch issuerPath for changes
// TODO restrict servicetoken audiences (and lifetimes)
func main() {
	addr := flag.String("addr", ":8080", "address to serve on")
	adminAddr := flag.String("admin-addr", ":9990", "address of HTTP admin server")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	issuerPath := flag.String("issuer",
		"/var/run/linkerd/identity/issuer",
		"path to directory containing issuer credentials")
	flags.ConfigureAndParse()

	cfg, err := config.Global(consts.MountPathGlobalConfig)
	if err != nil {
		log.Fatalf("Failed to load config: %s", err.Error())
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	controllerNS := cfg.GetLinkerdNamespace()
	idctx := cfg.GetIdentityContext()
	if idctx == nil {
		log.Infof("Identity disabled in control plane configuration.")
		os.Exit(0)
	}

	trustDomain := idctx.GetTrustDomain()
	dom, err := idctl.NewTrustDomain(controllerNS, trustDomain)
	if err != nil {
		log.Fatalf("Invalid trust domain: %s", err.Error())
	}

	issuanceLifetime := identity.DefaultIssuanceLifetime
	if pbd := idctx.GetIssuanceLifetime(); pbd != nil {
		il, err := ptypes.Duration(pbd)
		if err != nil {
			log.Warnf("Invalid issuance lifetime: %s, defaulting to 24h", err)
		} else {
			issuanceLifetime = il
		}
	}

	var ca tls.Issuer
	switch int(idctx.GetCaType()) {
	case idctl.LinkerdIdentityIssuer:
		trustAnchors, err := tls.DecodePEMCertPool(idctx.GetTrustAnchorsPem())
		if err != nil {
			log.Fatalf("Failed to read trust anchors: %s", err)
		}

		creds, err := tls.ReadPEMCreds(
			filepath.Join(*issuerPath, consts.IdentityIssuerKeyName),
			filepath.Join(*issuerPath, consts.IdentityIssuerCrtName),
		)
		if err != nil {
			log.Fatalf("Failed to read CA from %s: %s", *issuerPath, err)
		}

		expectedName := fmt.Sprintf("identity.%s.%s", controllerNS, trustDomain)
		if err := creds.Crt.Verify(trustAnchors, expectedName); err != nil {
			log.Fatalf("Failed to verify issuer credentials for '%s' with trust anchors: %s", expectedName, err)
		}

		validity := tls.Validity{
			ClockSkewAllowance: tls.DefaultClockSkewAllowance,
			Lifetime:           issuanceLifetime,
		}
		if pbd := idctx.GetClockSkewAllowance(); pbd != nil {
			csa, err := ptypes.Duration(pbd)
			if err != nil {
				log.Warnf("Invalid clock skew allowance: %s", err)
			} else {
				validity.ClockSkewAllowance = csa
			}
		}
		ca = tls.NewCA(*creds, validity)
	case idctl.AwsAcmPcaIssuer:
		region := idctx.GetAwsacmpca().GetCaRegion()
		arn := idctx.GetAwsacmpca().GetCaArn()
		requestRetryer, retryerErr := pcadelegate.NewACMPCARetry(5)
		if retryerErr != nil {
			log.Fatalf("Failed to create the ACMPCA request retryer: %v\n", retryerErr)
		}
		params := pcadelegate.CADelegateParams{
			Region:         region,
			CaARN:          arn,
			ValidityPeriod: issuanceLifetime,
			Retryer:        requestRetryer,
		}
		ca, err = pcadelegate.NewCADelegate(params)
		if err != nil {
			log.Fatalf("Failed to create the AWS ACM PCA Delegate: %v", err)
		}
	}

	k8s, err := k8s.NewAPI(*kubeConfigPath, "", 0)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %s: %s", *kubeConfigPath, err)
	}
	v, err := idctl.NewK8sTokenValidator(k8s, dom)
	if err != nil {
		log.Fatalf("Failed to initialize identity service: %s", err)
	}

	svc := identity.NewService(v, ca)

	go admin.StartServer(*adminAddr)
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %s", *addr, err)
	}

	srv := grpc.NewServer()
	identity.Register(srv, svc)
	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()
	<-stop
	log.Infof("shutting down gRPC server on %s", *addr)
	srv.GracefulStop()
}
