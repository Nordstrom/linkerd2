package identity

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"

	"github.com/golang/protobuf/ptypes"
	idctl "github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/charts"
	"github.com/linkerd/linkerd2/pkg/config"
	"github.com/linkerd/linkerd2/pkg/flags"
	"github.com/linkerd/linkerd2/pkg/identity"
	"github.com/linkerd/linkerd2/pkg/k8s"
	consts "github.com/linkerd/linkerd2/pkg/k8s"
	pcadelegate "github.com/linkerd/linkerd2/pkg/pcadelegate"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/trace"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1machinary "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// TODO watch trustAnchorsPath for changes
// TODO watch issuerPath for changes
// TODO restrict servicetoken audiences (and lifetimes)

// Main executes the identity subcommand
func Main(args []string) {
	cmd := flag.NewFlagSet("identity", flag.ExitOnError)

	addr := cmd.String("addr", ":8080", "address to serve on")
	adminAddr := cmd.String("admin-addr", ":9990", "address of HTTP admin server")
	kubeConfigPath := cmd.String("kubeconfig", "", "path to kube config")
	issuerPath := cmd.String("issuer",
		"/var/run/linkerd/identity/issuer",
		"path to directory containing issuer credentials")

	traceCollector := flags.AddTraceFlags(cmd)
	componentName := "linkerd-identity"

	flags.ConfigureAndParse(cmd, args)

	cfg, err := config.Global(consts.MountPathGlobalConfig)
	if err != nil {
		log.Fatalf("Failed to load config: %s", err.Error())
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controllerNS := cfg.GetLinkerdNamespace()
	idctx := cfg.GetIdentityContext()
	if idctx == nil {
		log.Infof("Identity disabled in control plane configuration.")
		os.Exit(0)
	}

	issuanceLifetime := identity.DefaultIssuanceLifetime
	if pbd := idctx.GetIssuer().GetIssuanceLifetime(); pbd != nil {
		il, err := ptypes.Duration(pbd)
		if err != nil {
			log.Warnf("Invalid issuance lifetime: %s, defaulting to 24h", err)
		} else {
			issuanceLifetime = il
		}
	}

	trustDomain := idctx.GetTrustDomain()
	dom, err := idctl.NewTrustDomain(controllerNS, trustDomain)
	if err != nil {
		log.Fatalf("Invalid trust domain: %s", err.Error())
	}

	trustAnchors, err := tls.DecodePEMCertPool(idctx.GetTrustAnchorsPem())
	if err != nil {
		log.Fatalf("Failed to read trust anchors: %s", err)
	}

	//
	// Create k8s API
	//
	k8sAPI, err := k8s.NewAPI(*kubeConfigPath, "", "", 0)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %s: %s", *kubeConfigPath, err)
	}
	v, err := idctl.NewK8sTokenValidator(k8sAPI, dom)
	if err != nil {
		log.Fatalf("Failed to initialize identity service: %s", err)
	}

	log.Debugf("Using issuer type: %s", idctx.GetIssuer().GetIssuerType())

	issuerEvent := make(chan struct{})
	issuerError := make(chan error)

	var svc *identity.Service
	switch idctx.GetIssuer().GetIssuerType() {
	case charts.LinkerdIdentityIssuerType:
		var issuerPathCrt string
		var issuerPathKey string
		if idctx.GetLinkerdIdentityIssuer().GetScheme() == k8s.IdentityIssuerSchemeLinkerd {
			issuerPathCrt = filepath.Join(*issuerPath, k8s.IdentityIssuerCrtName)
			issuerPathKey = filepath.Join(*issuerPath, k8s.IdentityIssuerKeyName)
		} else {
			issuerPathCrt = filepath.Join(*issuerPath, corev1.TLSCertKey)
			issuerPathKey = filepath.Join(*issuerPath, corev1.TLSPrivateKeyKey)
		}

		//
		// Create and start FS creds watcher
		//
		watcher := idctl.NewFsCredsWatcher(*issuerPath, issuerEvent, issuerError)
		go func() {
			if err := watcher.StartWatching(ctx); err != nil {
				log.Fatalf("Failed to start creds watcher: %s", err)
			}
		}()

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
		if pbd := idctx.GetLinkerdIdentityIssuer().GetClockSkewAllowance(); pbd != nil {
			csa, err := ptypes.Duration(pbd)
			if err != nil {
				log.Warnf("Invalid clock skew allowance: %s", err)
			} else {
				validity.ClockSkewAllowance = csa
			}
		}

		// Create K8s event recorder
		eventBroadcaster := record.NewBroadcaster()
		eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{
			Interface: k8sAPI.CoreV1().Events(controllerNS),
		})
		recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: componentName})
		deployment, err := k8sAPI.AppsV1().Deployments(controllerNS).Get(componentName, v1machinary.GetOptions{})

		if err != nil {
			log.Fatalf("Failed to construct k8s event recorder: %s", err)
		}

		recordEventFunc := func(eventType, reason, message string) {
			recorder.Event(deployment, eventType, reason, message)
		}

		//
		// Create, initialize and run service
		//
		svc = identity.NewService(v, trustAnchors, &validity, recordEventFunc, expectedName, issuerPathCrt, issuerPathKey)
		if err = svc.Initialize(); err != nil {
			log.Fatalf("Failed to initialize identity service: %s", err)
		}
		go func() {
			svc.Run(issuerEvent, issuerError)
		}()

	case charts.AwsAcmPcaIdentityIssuerType:
		region := idctx.GetAwsacmpcaIdentityIssuer().GetCaRegion()
		log.Debugf("awsacmpca configured region: %s", region)
		arn := idctx.GetAwsacmpcaIdentityIssuer().GetCaArn()
		log.Debugf("awsacmpca configured arn: %s", arn)
		requestRetryer, retryerErr := pcadelegate.NewACMPCARetry(5)
		if retryerErr != nil {
			log.Fatalf("Failed to create the ACMPCA request retryer: %v\n", retryerErr)
		}
		params := pcadelegate.CADelegateParams{
			Region:         region,
			CaARN:          arn,
			ValidityPeriod: issuanceLifetime,
			SigAlgorithm:   pcadelegate.Sha256withrsa,
			Retryer:        requestRetryer,
		}
		ca, err := pcadelegate.NewCADelegate(params)
		if err != nil {
			log.Fatalf("Failed to create the AWS ACM PCA Delegate: %v", err)
		}
		validity := tls.Validity{
			ClockSkewAllowance: tls.DefaultClockSkewAllowance,
			Lifetime:           issuanceLifetime,
		}
		svc = identity.NewACMPCAIdentityService(v, ca, trustAnchors, &validity)
	}

	//
	// Bind and serve
	//
	go admin.StartServer(*adminAddr)
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %s", *addr, err)
	}

	if *traceCollector != "" {
		if err := trace.InitializeTracing(componentName, *traceCollector); err != nil {
			log.Warnf("failed to initialize tracing: %s", err)
		}
	}
	srv := prometheus.NewGrpcServer()
	identity.Register(srv, svc)
	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()
	<-stop
	log.Infof("shutting down gRPC server on %s", *addr)
	srv.GracefulStop()
}
