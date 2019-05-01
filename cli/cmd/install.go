package cmd

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/linkerd/linkerd2/cli/static"
	pb "github.com/linkerd/linkerd2/controller/gen/config"
	identity "github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/pkg/config"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/helm/pkg/chartutil"
	"k8s.io/helm/pkg/proto/hapi/chart"
	"k8s.io/helm/pkg/renderutil"
	"k8s.io/helm/pkg/timeconv"
	"sigs.k8s.io/yaml"
)

type (
	installValues struct {
		stage string

		Namespace                string
		ControllerImage          string
		WebImage                 string
		PrometheusImage          string
		GrafanaImage             string
		ImagePullPolicy          string
		UUID                     string
		CliVersion               string
		ControllerReplicas       uint
		ControllerLogLevel       string
		PrometheusLogLevel       string
		ControllerComponentLabel string
		CreatedByAnnotation      string
		ProxyContainerName       string
		ProxyInjectAnnotation    string
		ProxyInjectDisabled      string
		ControllerUID            int64
		EnableH2Upgrade          bool
		NoInitContainer          bool

		Configs configJSONs

		DestinationResources,
		GrafanaResources,
		IdentityResources,
		PrometheusResources,
		ProxyInjectorResources,
		PublicAPIResources,
		SPValidatorResources,
		TapResources,
		WebResources *resources

		Identity *installIdentityValues
	}

	configJSONs struct{ Global, Proxy, Install string }

	resources   struct{ CPU, Memory constraints }
	constraints struct{ Request, Limit string }

	installIdentityValues struct {
		Replicas uint

		TrustDomain      string
		TrustAnchorsPEM  string
		IssuanceLifetime string

		AwsAcmPcaIssuer       *awsAcmPcaIssuerValues
		LinkerdIdentityIssuer *linkerdIdentityIssuerValues
	}

	awsAcmPcaIssuerValues struct {
		CaArn    string
		CaRegion string
	}

	linkerdIdentityIssuerValues struct {
		ClockSkewAllowance string

		KeyPEM, CrtPEM string

		CrtExpiry time.Time

		CrtExpiryAnnotation string
	}

	// installOptions holds values for command line flags that apply to the install
	// command. All fields in this struct should have corresponding flags added in
	// the newCmdInstall func later in this file. It also embeds proxyConfigOptions
	// in order to hold values for command line flags that apply to both inject and
	// install.
	installOptions struct {
		controlPlaneVersion string
		controllerReplicas  uint
		controllerLogLevel  string
		highAvailability    bool
		controllerUID       int64
		disableH2Upgrade    bool
		noInitContainer     bool
		skipChecks          bool
		identityOptions     *installIdentityOptions
		*proxyConfigOptions

		recordedFlags []*pb.Install_Flag

		// A function pointer that can be overridden for tests
		generateUUID func() string
	}

	installIdentityOptions struct {
		replicas         uint
		trustDomain      string
		trustPEMFile     string
		caType           int
		issuanceLifetime time.Duration

		*linkerdIdentityIssuerOptions
		*awsAcmPcaIssuerOptions
	}

	awsAcmPcaIssuerOptions struct {
		region, arn string
	}

	linkerdIdentityIssuerOptions struct {
		crtPEMFile, keyPEMFile string
		clockSkewAllowance     time.Duration
	}
)

const (
	configStage       = "config"
	controlPlaneStage = "control-plane"

	prometheusImage                   = "prom/prometheus:v2.7.1"
	prometheusProxyOutboundCapacity   = 10000
	defaultControllerReplicas         = 1
	defaultHAControllerReplicas       = 3
	defaultIdentityTrustDomain        = "cluster.local"
	defaultIdentityIssuanceLifetime   = 24 * time.Hour
	defaultIdentityClockSkewAllowance = 20 * time.Second
	defaultCaType                     = identity.LinkerdIdentityIssuer
)

// newInstallOptionsWithDefaults initializes install options with default
// control plane and proxy options.
//
// These options may be overridden on the CLI at install-time and will be
// persisted in Linkerd's control plane configuration to be used at
// injection-time.
func newInstallOptionsWithDefaults() *installOptions {
	return &installOptions{
		controlPlaneVersion: version.Version,
		controllerReplicas:  defaultControllerReplicas,
		controllerLogLevel:  "info",
		highAvailability:    false,
		controllerUID:       2103,
		disableH2Upgrade:    false,
		noInitContainer:     false,
		proxyConfigOptions: &proxyConfigOptions{
			proxyVersion:           version.Version,
			ignoreCluster:          false,
			proxyImage:             defaultDockerRegistry + "/proxy",
			initImage:              defaultDockerRegistry + "/proxy-init",
			dockerRegistry:         defaultDockerRegistry,
			imagePullPolicy:        "IfNotPresent",
			ignoreInboundPorts:     nil,
			ignoreOutboundPorts:    nil,
			proxyUID:               2102,
			proxyLogLevel:          "warn,linkerd2_proxy=info",
			proxyControlPort:       4190,
			proxyAdminPort:         4191,
			proxyInboundPort:       4143,
			proxyOutboundPort:      4140,
			proxyCPURequest:        "",
			proxyMemoryRequest:     "",
			proxyCPULimit:          "",
			proxyMemoryLimit:       "",
			enableExternalProfiles: false,
		},
		identityOptions: newInstallIdentityOptionsWithDefaults(),

		generateUUID: func() string {
			id, err := uuid.NewRandom()
			if err != nil {
				log.Fatalf("Could not generate UUID: %s", err)
			}
			return id.String()
		},
	}
}

func newInstallIdentityOptionsWithDefaults() *installIdentityOptions {
	return &installIdentityOptions{
		trustDomain:                  defaultIdentityTrustDomain,
		caType:                       defaultCaType,
		issuanceLifetime:             defaultIdentityIssuanceLifetime,
		linkerdIdentityIssuerOptions: newLinkerdIdentityIssuerOptionsWithDefaults(),
		awsAcmPcaIssuerOptions:       newAwsAcmPcaOptionsWithDefaults(),
	}
}

func newLinkerdIdentityIssuerOptionsWithDefaults() *linkerdIdentityIssuerOptions {
	return &linkerdIdentityIssuerOptions{
		clockSkewAllowance: defaultIdentityClockSkewAllowance,
	}
}

func newAwsAcmPcaOptionsWithDefaults() *awsAcmPcaIssuerOptions {
	return &awsAcmPcaIssuerOptions{}
}

func newCmdInstall() *cobra.Command {
	options := newInstallOptionsWithDefaults()

	// The base flags are recorded separately so that they can be serialized into
	// the configuration in validateAndBuild.
	flags := options.recordableFlagSet()
	installOnlyFlags := options.installOnlyFlagSet()

	cmd := &cobra.Command{
		Use:       fmt.Sprintf("install [%s|%s] [flags]", configStage, controlPlaneStage),
		Args:      cobra.OnlyValidArgs,
		ValidArgs: []string{configStage, controlPlaneStage},
		Short:     "Output Kubernetes configs to install Linkerd",
		Long: `Output Kubernetes configs to install Linkerd.

This command provides Kubernetes configs necessary to install the Linkerd
control-plane.`,
		Example: `  # Default install.
  linkerd install | kubectl apply -f -

  # Installation may also be broken up into two stages, by user privilege.
  # First stage requires cluster-level privileges.
  linkerd install config | kubectl apply -f -
  # Second stage requires namespace-level privileges.
  linkerd install control-plane | kubectl apply -f -

  # Install Linkerd into a non-default namespace.
  linkerd install config -l linkerdtest | kubectl apply -f -
  linkerd install control-plane -l linkerdtest | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			stage, err := validateArgs(args, flags, installOnlyFlags)
			if err != nil {
				return err
			}
			if !options.ignoreCluster {
				// TODO: consider cobra.SilenceUsage, so we can return errors from
				// `RunE`, rather than calling `os.Exit(1)`
				exitIfClusterExists()
			}
			if !options.skipChecks && stage == controlPlaneStage {
				exitIfNamespaceDoesNotExist()
			}

			values, configs, err := options.validateAndBuild(stage, flags)
			if err != nil {
				return err
			}

			return values.render(os.Stdout, configs)
		},
	}

	cmd.PersistentFlags().AddFlagSet(flags)

	// Some flags are not available during upgrade, etc.
	cmd.PersistentFlags().AddFlagSet(installOnlyFlags)

	return cmd
}

func (options *installOptions) validateAndBuild(stage string, flags *pflag.FlagSet) (*installValues, *pb.All, error) {
	if err := options.validate(); err != nil {
		return nil, nil, err
	}
	options.recordFlags(flags)

	identityValues, err := options.identityOptions.validateAndBuild()
	if err != nil {
		return nil, nil, err
	}

	configs := options.configs(identityValues.toIdentityContext())

	values, err := options.buildValuesWithoutIdentity(configs)
	if err != nil {
		return nil, nil, err
	}
	values.Identity = identityValues
	values.stage = stage

	return values, configs, nil
}

// recordableFlagSet returns flags usable during install or upgrade.
func (options *installOptions) recordableFlagSet() *pflag.FlagSet {
	e := pflag.ExitOnError

	flags := pflag.NewFlagSet("install", e)

	flags.AddFlagSet(options.proxyConfigOptions.flagSet(e))

	flags.UintVar(
		&options.controllerReplicas, "controller-replicas", options.controllerReplicas,
		"Replicas of the controller to deploy",
	)

	flags.BoolVar(&options.noInitContainer, "linkerd-cni-enabled", options.noInitContainer,
		"Experimental: Omit the proxy-init container when injecting the proxy; requires the linkerd-cni plugin to already be installed",
	)

	flags.StringVar(
		&options.controllerLogLevel, "controller-log-level", options.controllerLogLevel,
		"Log level for the controller and web components",
	)
	flags.BoolVar(
		&options.highAvailability, "ha", options.highAvailability,
		"Experimental: Enable HA deployment config for the control plane (default false)",
	)
	flags.Int64Var(
		&options.controllerUID, "controller-uid", options.controllerUID,
		"Run the control plane components under this user ID",
	)
	flags.BoolVar(
		&options.disableH2Upgrade, "disable-h2-upgrade", options.disableH2Upgrade,
		"Prevents the controller from instructing proxies to perform transparent HTTP/2 upgrading (default false)",
	)
	flags.StringVar(
		&options.identityOptions.region, "identity-ca-region", options.identityOptions.region,
		"The region where the CA is located.",
	)
	flags.StringVar(
		&options.identityOptions.arn, "identity-ca-arn", options.identityOptions.arn,
		"The arn of the CA.",
	)
	flags.DurationVar(
		&options.identityOptions.issuanceLifetime, "identity-issuance-lifetime", options.identityOptions.issuanceLifetime,
		"The amount of time for which the Identity issuer should certify identity",
	)
	flags.DurationVar(
		&options.identityOptions.clockSkewAllowance, "identity-clock-skew-allowance", options.identityOptions.clockSkewAllowance,
		"The amount of time to allow for clock skew within a Linkerd cluster",
	)

	flags.StringVarP(&options.controlPlaneVersion, "control-plane-version", "", options.controlPlaneVersion, "(Development) Tag to be used for the control plane component images")
	flags.MarkHidden("control-plane-version")

	return flags
}

// installOnlyFlagSet includes flags that are only accessible at install-time
// and not at upgrade-time.
func (options *installOptions) installOnlyFlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("install-only", pflag.ExitOnError)

	flags.StringVar(
		&options.identityOptions.trustDomain, "identity-trust-domain", options.identityOptions.trustDomain,
		"Configures the name suffix used for identities.",
	)
	flags.StringVar(
		&options.identityOptions.trustPEMFile, "identity-trust-anchors-file", options.identityOptions.trustPEMFile,
		"A path to a PEM-encoded file containing Linkerd Identity trust anchors (generated by default)",
	)
	flags.StringVar(
		&options.identityOptions.crtPEMFile, "identity-issuer-certificate-file", options.identityOptions.crtPEMFile,
		"A path to a PEM-encoded file containing the Linkerd Identity issuer certificate (generated by default)",
	)
	flags.StringVar(
		&options.identityOptions.keyPEMFile, "identity-issuer-key-file", options.identityOptions.keyPEMFile,
		"A path to a PEM-encoded file containing the Linkerd Identity issuer private key (generated by default)",
	)
	flags.IntVar(
		&options.identityOptions.caType, "identity-ca-type", options.identityOptions.caType,
		"The type of CA to use for issuing proxy certificates. (0 = linkerd-identity (default), 1 = awsacmpca)",
	)

	flags.BoolVar(
		&options.ignoreCluster, "ignore-cluster", options.ignoreCluster,
		"Ignore the current Kubernetes cluster when checking for existing cluster configuration (default false)",
	)
	flags.BoolVar(
		&options.skipChecks, "skip-checks", options.skipChecks,
		`Skip checks for namespace existence, applicable for "linkerd install control-plane"`,
	)

	return flags
}

func (options *installOptions) recordFlags(flags *pflag.FlagSet) {
	if flags == nil {
		return
	}

	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			switch f.Name {
			case "ignore-cluster", "control-plane-version", "proxy-version":
				// These flags don't make sense to record.
			default:
				options.recordedFlags = append(options.recordedFlags, &pb.Install_Flag{
					Name:  f.Name,
					Value: f.Value.String(),
				})
			}
		}
	})
}

func (options *installOptions) validate() error {
	if options.controlPlaneVersion != "" && !alphaNumDashDot.MatchString(options.controlPlaneVersion) {
		return fmt.Errorf("%s is not a valid version", options.controlPlaneVersion)
	}

	if options.identityOptions == nil {
		// Programmer error: identityOptions may be empty, but it must be set by the constructor.
		panic("missing identity options")
	}

	if _, err := log.ParseLevel(options.controllerLogLevel); err != nil {
		return fmt.Errorf("--controller-log-level must be one of: panic, fatal, error, warn, info, debug")
	}

	if err := options.proxyConfigOptions.validate(); err != nil {
		return err
	}
	if options.proxyLogLevel == "" {
		return errors.New("--proxy-log-level must not be empty")
	}

	if options.highAvailability {
		if options.controllerReplicas == defaultControllerReplicas {
			options.controllerReplicas = defaultHAControllerReplicas
		}

		if options.proxyCPURequest == "" {
			options.proxyCPURequest = "100m"
		}

		if options.proxyMemoryRequest == "" {
			options.proxyMemoryRequest = "20Mi"
		}
	}

	options.identityOptions.replicas = options.controllerReplicas

	return nil
}

func (options *installOptions) buildValuesWithoutIdentity(configs *pb.All) (*installValues, error) {
	globalJSON, proxyJSON, installJSON, err := config.ToJSON(configs)
	if err != nil {
		return nil, err
	}

	values := &installValues{
		// Container images:
		ControllerImage: fmt.Sprintf("%s/controller:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		WebImage:        fmt.Sprintf("%s/web:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		GrafanaImage:    fmt.Sprintf("%s/grafana:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		PrometheusImage: prometheusImage,
		ImagePullPolicy: options.imagePullPolicy,

		// Kubernetes labels/annotations/resourcse:
		CreatedByAnnotation:      k8s.CreatedByAnnotation,
		CliVersion:               k8s.CreatedByAnnotationValue(),
		ControllerComponentLabel: k8s.ControllerComponentLabel,
		ProxyContainerName:       k8s.ProxyContainerName,
		ProxyInjectAnnotation:    k8s.ProxyInjectAnnotation,
		ProxyInjectDisabled:      k8s.ProxyInjectDisabled,

		// Controller configuration:
		Namespace:          controlPlaneNamespace,
		UUID:               configs.GetInstall().GetUuid(),
		ControllerReplicas: options.controllerReplicas,
		ControllerLogLevel: options.controllerLogLevel,
		ControllerUID:      options.controllerUID,
		EnableH2Upgrade:    !options.disableH2Upgrade,
		NoInitContainer:    options.noInitContainer,
		PrometheusLogLevel: toPromLogLevel(options.controllerLogLevel),

		Configs: configJSONs{
			Global:  globalJSON,
			Proxy:   proxyJSON,
			Install: installJSON,
		},

		DestinationResources:   &resources{},
		GrafanaResources:       &resources{},
		IdentityResources:      &resources{},
		PrometheusResources:    &resources{},
		ProxyInjectorResources: &resources{},
		PublicAPIResources:     &resources{},
		SPValidatorResources:   &resources{},
		TapResources:           &resources{},
		WebResources:           &resources{},
	}

	if options.highAvailability {
		defaultConstraints := &resources{
			CPU:    constraints{Request: "100m"},
			Memory: constraints{Request: "50Mi"},
		}
		// Copy constraints to each so that further modification isn't global.
		*values.DestinationResources = *defaultConstraints
		*values.GrafanaResources = *defaultConstraints
		*values.ProxyInjectorResources = *defaultConstraints
		*values.PublicAPIResources = *defaultConstraints
		*values.SPValidatorResources = *defaultConstraints
		*values.TapResources = *defaultConstraints
		*values.WebResources = *defaultConstraints

		// The identity controller maintains no internal state, so it need not request
		// 50Mi.
		*values.IdentityResources = *defaultConstraints
		values.IdentityResources.Memory = constraints{Request: "10Mi"}

		values.PrometheusResources = &resources{
			CPU:    constraints{Request: "300m"},
			Memory: constraints{Request: "300Mi"},
		}
	}

	return values, nil
}

func toPromLogLevel(level string) string {
	switch level {
	case "panic", "fatal":
		return "error"
	default:
		return level
	}
}

// TODO: are `installValues.Configs` and `configs` redundant?
func (values *installValues) render(w io.Writer, configs *pb.All) error {
	// Render raw values and create chart config
	rawValues, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	chrtConfig := &chart.Config{Raw: string(rawValues), Values: map[string]*chart.Value{}}

	files := []*chartutil.BufferedFile{
		{Name: chartutil.ChartfileName},
	}

	if values.stage == "" || values.stage == configStage {
		files = append(files, []*chartutil.BufferedFile{
			{Name: "templates/namespace.yaml"},
			{Name: "templates/identity-rbac.yaml"},
			{Name: "templates/controller-rbac.yaml"},
			{Name: "templates/web-rbac.yaml"},
			{Name: "templates/serviceprofile-crd.yaml"},
			{Name: "templates/prometheus-rbac.yaml"},
			{Name: "templates/grafana-rbac.yaml"},
			{Name: "templates/proxy_injector-rbac.yaml"},
			{Name: "templates/sp_validator-rbac.yaml"},
		}...)
	}

	if values.stage == "" || values.stage == controlPlaneStage {
		files = append(files, []*chartutil.BufferedFile{
			{Name: "templates/_resources.yaml"},
			{Name: "templates/config.yaml"},
			{Name: "templates/identity.yaml"},
			{Name: "templates/controller.yaml"},
			{Name: "templates/web.yaml"},
			{Name: "templates/prometheus.yaml"},
			{Name: "templates/grafana.yaml"},
			{Name: "templates/proxy_injector.yaml"},
			{Name: "templates/sp_validator.yaml"},
		}...)
	}

	// Read templates into bytes
	for _, f := range files {
		data, err := readIntoBytes(f.Name)
		if err != nil {
			return err
		}
		f.Data = data
	}

	// Create chart and render templates
	chrt, err := chartutil.LoadFiles(files)
	if err != nil {
		return err
	}

	renderOpts := renderutil.Options{
		ReleaseOptions: chartutil.ReleaseOptions{
			Name:      "linkerd",
			IsInstall: true,
			IsUpgrade: false,
			Time:      timeconv.Now(),
			Namespace: controlPlaneNamespace,
		},
		KubeVersion: "",
	}

	renderedTemplates, err := renderutil.Render(chrt, chrtConfig, renderOpts)
	if err != nil {
		return err
	}

	// Merge templates and inject
	var buf bytes.Buffer
	for _, tmpl := range files {
		t := path.Join(renderOpts.ReleaseOptions.Name, tmpl.Name)
		if _, err := buf.WriteString(renderedTemplates[t]); err != nil {
			return err
		}
	}

	// Skip outbound port 443 to enable Kubernetes API access without the proxy.
	// Once Kubernetes supports sidecar containers, this may be removed, as that
	// will guarantee the proxy is running prior to control-plane startup.
	configs.Proxy.IgnoreOutboundPorts = append(configs.Proxy.IgnoreOutboundPorts, &pb.Port{Port: 443})

	return processYAML(&buf, w, ioutil.Discard, resourceTransformerInject{
		injectProxy: true,
		configs:     configs,
		proxyOutboundCapacity: map[string]uint{
			values.PrometheusImage: prometheusProxyOutboundCapacity,
		},
	})
}

func readIntoBytes(filename string) ([]byte, error) {
	file, err := static.Templates.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)

	return buf.Bytes(), nil
}

func (options *installOptions) configs(identity *pb.IdentityContext) *pb.All {
	return &pb.All{
		Global:  options.globalConfig(identity),
		Proxy:   options.proxyConfig(),
		Install: options.installConfig(),
	}
}

func (options *installOptions) globalConfig(identity *pb.IdentityContext) *pb.Global {
	return &pb.Global{
		LinkerdNamespace: controlPlaneNamespace,
		CniEnabled:       options.noInitContainer,
		Version:          options.controlPlaneVersion,
		IdentityContext:  identity,
	}
}

func (options *installOptions) installConfig() *pb.Install {
	installID := ""
	if options.generateUUID != nil {
		installID = options.generateUUID()
	}

	return &pb.Install{
		Uuid:       installID,
		CliVersion: version.Version,
		Flags:      options.recordedFlags,
	}
}

func (options *installOptions) proxyConfig() *pb.Proxy {
	ignoreInboundPorts := []*pb.Port{}
	for _, port := range options.ignoreInboundPorts {
		ignoreInboundPorts = append(ignoreInboundPorts, &pb.Port{Port: uint32(port)})
	}

	ignoreOutboundPorts := []*pb.Port{}
	for _, port := range options.ignoreOutboundPorts {
		ignoreOutboundPorts = append(ignoreOutboundPorts, &pb.Port{Port: uint32(port)})
	}

	return &pb.Proxy{
		ProxyImage: &pb.Image{
			ImageName:  registryOverride(options.proxyImage, options.dockerRegistry),
			PullPolicy: options.imagePullPolicy,
		},
		ProxyInitImage: &pb.Image{
			ImageName:  registryOverride(options.initImage, options.dockerRegistry),
			PullPolicy: options.imagePullPolicy,
		},
		ControlPort: &pb.Port{
			Port: uint32(options.proxyControlPort),
		},
		IgnoreInboundPorts:  ignoreInboundPorts,
		IgnoreOutboundPorts: ignoreOutboundPorts,
		InboundPort: &pb.Port{
			Port: uint32(options.proxyInboundPort),
		},
		AdminPort: &pb.Port{
			Port: uint32(options.proxyAdminPort),
		},
		OutboundPort: &pb.Port{
			Port: uint32(options.proxyOutboundPort),
		},
		Resource: &pb.ResourceRequirements{
			RequestCpu:    options.proxyCPURequest,
			RequestMemory: options.proxyMemoryRequest,
			LimitCpu:      options.proxyCPULimit,
			LimitMemory:   options.proxyMemoryLimit,
		},
		ProxyUid: options.proxyUID,
		LogLevel: &pb.LogLevel{
			Level: options.proxyLogLevel,
		},
		DisableExternalProfiles: !options.enableExternalProfiles,
		ProxyVersion:            options.proxyVersion,
	}
}

// exitIfClusterExists checks the kubernetes API to determine
// whether a config exists and exits if it does exist or if an error is
// encountered.
//
// This bypasses the public API so that public API errors cannot cause us to
// misdiagnose a controller error to indicate that no control plane exists.
func exitIfClusterExists() {
	k, err := k8s.NewAPI(kubeconfigPath, kubeContext, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to build a Kubernetes client to check for configuration. If this expected, use the --ignore-cluster flag.")
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	c := k.CoreV1().ConfigMaps(controlPlaneNamespace)
	if _, err = c.Get(k8s.ConfigConfigMapName, metav1.GetOptions{}); err != nil {
		if kerrors.IsNotFound(err) {
			return
		}

		fmt.Fprintln(os.Stderr, "Unable to build a Kubernetes client to check for configuration. If this expected, use the --ignore-cluster flag.")
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Linkerd has already been installed on your cluster in the linkerd namespace. Please run upgrade if you'd like to update this installation. Otherwise, use the --ignore-cluster flag.")
	os.Exit(1)
}

// exitIfNamespaceDoesNotExist checks the kubernetes API to determine if the
// control-plane namespace exists, and returns an error if it does not.
//
// This is useful when running `linkerd install control-plane`, where the
// namespace must exist, but `linkerd-config` should not.
func exitIfNamespaceDoesNotExist() {
	hc := newHealthChecker(
		[]healthcheck.CategoryID{healthcheck.KubernetesAPIChecks},
		time.Time{},
	)

	success := hc.RunChecks(exitOnError)
	if !success {
		fmt.Fprintln(os.Stderr, "Failed to connect to Kubernetes. If this expected, use the --skip-checks flag.")
		os.Exit(1)
	}

	err := hc.CheckNamespace(controlPlaneNamespace, true)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Failed to find required control-plane namespace: %s. Run \"linkerd install config -l %s | kubectl apply -f -\" to create it (this requires cluster administration permissions).\nSee https://linkerd.io/2/getting-started/ for more information. Or use \"--skip-checks\" to proceed anyway.\n",
			controlPlaneNamespace, controlPlaneNamespace,
		)
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func (idopts *installIdentityOptions) validate() error {
	if idopts == nil {
		return nil
	}

	switch caType := idopts.caType; caType {
	case identity.LinkerdIdentityIssuer:
		if idopts.trustDomain != "" {
			if errs := validation.IsDNS1123Subdomain(idopts.trustDomain); len(errs) > 0 {
				return fmt.Errorf("invalid trust domain '%s': %s", idopts.trustDomain, errs[0])
			}
		}

		if idopts.trustPEMFile != "" || idopts.crtPEMFile != "" || idopts.keyPEMFile != "" {
			if idopts.trustPEMFile == "" {
				return errors.New("a trust anchors file must be specified if other credentials are provided")
			}
			if idopts.crtPEMFile == "" {
				return errors.New("a certificate file must be specified if other credentials are provided")
			}
			if idopts.keyPEMFile == "" {
				return errors.New("a private key file must be specified if other credentials are provided")
			}

			for _, f := range []string{idopts.trustPEMFile, idopts.crtPEMFile, idopts.keyPEMFile} {
				stat, err := os.Stat(f)
				if err != nil {
					return fmt.Errorf("missing file: %s", err)
				}
				if stat.IsDir() {
					return fmt.Errorf("not a file: %s", f)
				}
			}
		}
	case identity.AwsAcmPcaIssuer:
		if len(idopts.region) == 0 {
			return errors.New("a region must be specified if using the awsacmpca caType")
		}
		if len(idopts.arn) == 0 {
			return errors.New("the awsacmpca arn must be specified if using the awsacmpca caType")
		}
		if len(idopts.trustPEMFile) == 0 {
			return errors.New("a trust anchors file must be specified if uswing the awsacmpca caType")
		}
		if idopts.issuanceLifetime < time.Hour*24 {
			return errors.New("an issuance lifetime of > 1 day must be provided if using the awsacmpca caType")
		}

		stat, err := os.Stat(idopts.trustPEMFile)
		if err != nil {
			return fmt.Errorf("missing file: %s", err)
		}
		if stat.IsDir() {
			return fmt.Errorf("not a file: %s", idopts.trustPEMFile)
		}
	}

	return nil
}

func (idopts *installIdentityOptions) validateAndBuild() (*installIdentityValues, error) {
	if idopts == nil {
		return nil, nil
	}

	if err := idopts.validate(); err != nil {
		return nil, err
	}

	switch idopts.caType {
	case identity.LinkerdIdentityIssuer:
		if idopts.trustPEMFile != "" && idopts.crtPEMFile != "" && idopts.keyPEMFile != "" {
			return idopts.readValues()
		}
	case identity.AwsAcmPcaIssuer:
		if len(idopts.trustPEMFile) > 0 {
			_, trustAnchorsPEM, err := idopts.readTrustAnchorsPemFile()
			if err != nil {
				return nil, err
			}

			return &installIdentityValues{
				Replicas:         idopts.replicas,
				TrustDomain:      idopts.trustDomain,
				TrustAnchorsPEM:  trustAnchorsPEM,
				IssuanceLifetime: idopts.issuanceLifetime.String(),
				AwsAcmPcaIssuer: &awsAcmPcaIssuerValues{
					CaArn:    idopts.arn,
					CaRegion: idopts.region,
				},
			}, nil
		}
	}

	return idopts.genValues()
}

func (idopts *installIdentityOptions) issuerName() string {
	return fmt.Sprintf("identity.%s.%s", controlPlaneNamespace, idopts.trustDomain)
}

func (idopts *installIdentityOptions) genValues() (*installIdentityValues, error) {
	root, err := tls.GenerateRootCAWithDefaults(idopts.issuerName())
	if err != nil {
		return nil, fmt.Errorf("failed to generate root certificate for identity: %s", err)
	}

	return &installIdentityValues{
		Replicas:         idopts.replicas,
		TrustDomain:      idopts.trustDomain,
		TrustAnchorsPEM:  root.Cred.Crt.EncodeCertificatePEM(),
		IssuanceLifetime: idopts.issuanceLifetime.String(),
		LinkerdIdentityIssuer: &linkerdIdentityIssuerValues{
			ClockSkewAllowance:  idopts.clockSkewAllowance.String(),
			CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,

			KeyPEM: root.Cred.EncodePrivateKeyPEM(),
			CrtPEM: root.Cred.Crt.EncodeCertificatePEM(),

			CrtExpiry: root.Cred.Crt.Certificate.NotAfter,
		},
	}, nil
}

// readValues attempts to read an issuer configuration from disk
// to produce an `installIdentityValues`.
//
// The identity options must have already been validated.
func (idopts *installIdentityOptions) readValues() (*installIdentityValues, error) {
	creds, err := tls.ReadPEMCreds(idopts.keyPEMFile, idopts.crtPEMFile)
	if err != nil {
		return nil, err
	}

	roots, trustAnchorsPEM, err := idopts.readTrustAnchorsPemFile()
	if err != nil {
		return nil, err
	}

	if err := creds.Verify(roots, idopts.issuerName()); err != nil {
		return nil, fmt.Errorf("invalid credentials: %s", err)
	}

	return &installIdentityValues{
		Replicas:         idopts.replicas,
		TrustDomain:      idopts.trustDomain,
		TrustAnchorsPEM:  trustAnchorsPEM,
		IssuanceLifetime: idopts.issuanceLifetime.String(),
		LinkerdIdentityIssuer: &linkerdIdentityIssuerValues{
			ClockSkewAllowance:  idopts.clockSkewAllowance.String(),
			CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,

			KeyPEM: creds.EncodePrivateKeyPEM(),
			CrtPEM: creds.EncodeCertificatePEM(),

			CrtExpiry: creds.Crt.Certificate.NotAfter,
		},
	}, nil
}

func (idopts *installIdentityOptions) readTrustAnchorsPemFile() (*x509.CertPool, string, error) {
	trustb, err := ioutil.ReadFile(idopts.trustPEMFile)
	if err != nil {
		return nil, "", err
	}

	trustAnchorsPEM := string(trustb)
	roots, err := tls.DecodePEMCertPool(trustAnchorsPEM)
	if err != nil {
		return nil, "", err
	}

	return roots, trustAnchorsPEM, nil
}

func (idvals *installIdentityValues) toIdentityContext() *pb.IdentityContext {
	if idvals == nil {
		return nil
	}

	identityContext := &pb.IdentityContext{
		TrustDomain:     idvals.TrustDomain,
		TrustAnchorsPem: idvals.TrustAnchorsPEM,
	}
	il, err := time.ParseDuration(idvals.IssuanceLifetime)
	if err != nil {
		il = defaultIdentityIssuanceLifetime
	}
	identityContext.IssuanceLifetime = ptypes.DurationProto(il)

	if idvals.LinkerdIdentityIssuer != nil {
		identityContext.CaType = 0
		csa, err := time.ParseDuration(idvals.LinkerdIdentityIssuer.ClockSkewAllowance)
		if err != nil {
			csa = defaultIdentityClockSkewAllowance
		}
		identityContext.ClockSkewAllowance = ptypes.DurationProto(csa)
	} else if idvals.AwsAcmPcaIssuer != nil {
		identityContext.CaType = 1
		awsacmpcaContext := &pb.IdentityContext_AwsAcmPca{
			CaArn:    idvals.AwsAcmPcaIssuer.CaArn,
			CaRegion: idvals.AwsAcmPcaIssuer.CaRegion,
		}
		identityContext.Awsacmpca = awsacmpcaContext
	}

	return identityContext
}

func validateArgs(args []string, flags *pflag.FlagSet, additionalFlags *pflag.FlagSet) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("only zero or one argument permitted, received: %s", args)
	} else if len(args) == 0 {
		return "", nil
	}

	stage := args[0]

	// only a few flags are available for config stage
	if stage == configStage {
		combinedFlags := pflag.NewFlagSet("combined-flags", pflag.ExitOnError)
		combinedFlags.AddFlagSet(flags)
		combinedFlags.AddFlagSet(additionalFlags)

		invalidFlags := make([]string, 0)
		combinedFlags.VisitAll(func(f *pflag.Flag) {
			if f.Changed {
				switch f.Name {
				case "ignore-cluster":
					// allow `linkerd install config --ignore-cluster`
				default:
					invalidFlags = append(invalidFlags, f.Name)
				}
			}
		})
		if len(invalidFlags) > 0 {
			err := fmt.Errorf("flags not available for config stage: --%s", strings.Join(invalidFlags, ", --"))
			return "", err
		}
	}

	return stage, nil
}
