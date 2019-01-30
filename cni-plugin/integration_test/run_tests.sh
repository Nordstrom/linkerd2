#!/bin/bash

# Helper function to find out when calico.conf/conflist file shows up
doesCalicoExist() {
  # find out if calico is in /etc/cni/net.d/ folder
  simplematch=$(minikube ssh 'ls /etc/cni/net.d | grep calico.conf')
  trimmedmatch=$(echo "$simplematch" | tr -d '[:space:]')
  if [ "$trimmedmatch" != "" ]; then echo "0"; else echo "1"; fi
}

echo "-------------------Killing Minikube"
minikube stop
minikube delete
rm -rf ~/.minikube

echo "-------------------Creating Minikube"
minikube start --kubernetes-version v1.10.8 --memory 8192 --cpus 4 --network-plugin=cni --extra-config=kubelet.network-plugin=cni

echo "-------------------Applying Calico"
kubectl apply -f https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/hosted/etcd.yaml
kubectl apply -f https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/hosted/calico.yaml

echo "-------------------Waiting for Calico components to become ready"
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=calico-etcd
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=calico-kube-controllers
kubectl wait --for=condition=ready pod -n kube-system -l k8s-app=calico-node

echo "-------------------Docker saving the proxy image"
dockersave.sh proxy dev-eff66c36-x37y
echo "-------------------Docker saving the cni-plugin image"
dockersave.sh cni-plugin dev-eff66c36-x37y

echo "-------------------Discover the calico conf file in /etc/cni/net.d"
# adapted from https://superuser.com/questions/878640/unix-script-wait-until-a-file-exists
calico_retry="10" # 10 seconds as default timeout
echo "Find calico.conf/conflist retry countdown starts at $wait_seconds"
sleepy_time="3"
echo "Sleep time between Calico.conf/conflist retries set to $sleepy_time"

doesExist=$(doesCalicoExist)
until [ $calico_retry -eq 0 -o $doesExist = "0" ]
do
  echo "Waiting for calico file to appear, $calico_retry retries left"
  sleep $sleepy_time
  doesExist=$(doesCalicoExist)
  calico_retry=$((calico_retry-1))
done

if [ $((wait_seconds)) -eq 0 -a $doesExist = "1" ]
then
  echo "could not find calico in /etc/cni/net.d"
  exit 1
else
  echo "found calico conf file in /etc/cni/net.d"
fi

echo "-------------------Applying linkerd-cni plugin"
kubectl apply -f $GOPATH/src/github.com/linkerd/linkerd2/cni-plugin/integration_test/iptables/cni-bootstrap.yaml

echo "-------------------Waiting for linkerd-cni components to become ready"
kubectl wait --for=condition=ready pod -n linkerd -l k8s-app=linkerd-cni

echo "-------------------Running tests"
#CNI_LAB_YAML_FILE=iptables/redirect-all-iptablestest-lab.yaml CNI_TEST_FUNCTION=TestPodRedirectsAllPorts ./../../bin/mkube ./test_setup.sh
CNI_LAB_YAML_FILE=$1 CNI_TEST_FUNCTION=$2 ./../../bin/mkube ./test_setup.sh

echo "-------------------Cleanup cni lab yaml"
kubectl delete -f $1
