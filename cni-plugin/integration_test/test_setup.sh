#!/bin/bash

# define some colors to use for output
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
LIME_YELLOW=$(tput setaf 190)
POWDER_BLUE=$(tput setaf 153)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BRIGHT=$(tput bold)
NORMAL=$(tput sgr0)
BLINK=$(tput blink)
REVERSE=$(tput smso)
UNDERLINE=$(tput smul)

function get_ip_for_pod(){
    local pod_name=$1
    until kubectl get pod ${pod_name} -o jsonpath='{.status.phase}' | grep Running > /dev/null ; do sleep 1 ; done

    local pod_ip=`kubectl get pod ${pod_name} --template={{.status.podIP}}`
    echo "${pod_ip}"
}

function wait_for_k8s_job_completion(){
    local job_name=$1
    until kubectl get jobs ${job_name} -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' | grep True ; do printf "." && sleep 1 ; done
}

function header(){
    local msg=$1
    printf "\n${REVERSE}${msg}${NORMAL}\n"
}

function log(){
    local msg=$1
    printf "${WHITE}${msg}${NORMAL}\n"
}

TESTER_JOB_NAME=cni-iptables-tester

REDIRECTS_ALL_FILE=iptables/redirect-all-iptablestest-lab.yaml
NO_RULES_FILE=iptables/no-rules-iptablestest-lab.yaml

header "Deleting any existing objects from previous test runs..."
kubectl delete -f ${REDIRECTS_ALL_FILE}
kubectl delete -f ${NO_RULES_FILE}
kubectl delete jobs/${TESTER_JOB_NAME}

header "Building the image used in tests..."
docker build . -f iptables/Dockerfile-tester --tag buoyantio/cni-iptables-tester:v1
sleep 10

header "Creating the test lab... redirects-all pod with linkerd injection and no-rules pod"
cat ${REDIRECTS_ALL_FILE} | ./../../target/cli/darwin/linkerd inject --linkerd-cni-enabled - | kubectl apply -f -
kubectl apply -f ${NO_RULES_FILE}

POD_WITH_NO_RULES_IP=$(get_ip_for_pod "pod-with-no-rules")
log "POD_WITH_NO_RULES_OP=${POD_WITH_NO_RULES_IP}"
POD_REDIRECTS_ALL_PORTS_IP=$(get_ip_for_pod "pod-redirects-all-ports")
log "POD_REDIRECTS_ALL_PORTS_IP=${POD_REDIRECTS_ALL_PORTS_IP}"

header "Running tester..."
cat <<EOF | kubectl create -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${TESTER_JOB_NAME}
spec:
  template:
    metadata:
      name: ${TESTER_JOB_NAME}
    spec:
      containers:
      - name: tester
        image: buoyantio/cni-iptables-tester:v1
        env:
          - name: POD_REDIRECTS_ALL_PORTS_IP
            value: ${POD_REDIRECTS_ALL_PORTS_IP}
          - name: POD_WITH_NO_RULES_IP
            value: ${POD_WITH_NO_RULES_IP}
        command: ["sh", "-c", "cd /go && (go test cni_rules_test.go -v -integration-tests; echo \"status:$?\")"]
      restartPolicy: Never
EOF

wait_for_k8s_job_completion $TESTER_JOB_NAME

header "Test output:"
kubectl logs jobs/${TESTER_JOB_NAME}

# Makes this script return status 0 if the test returned status 0
kubectl logs jobs/${TESTER_JOB_NAME} 2>&1 | grep "status:0" > /dev/null
