#!/bin/sh
# =============================================================================
# tests/k8s-stub.sh - turn a test image into a container + Kubernetes host.
#
# A real container runtime is installed (Docker on Debian/Ubuntu, rootful
# Podman with its API socket on the RHEL family): the assertions start
# containers after hardening, so forwarding, NAT, overlayfs and the firewall
# are tested for real. Kubernetes itself cannot run in this container, so a
# kubeadm control-plane node is laid out the way the script detects it:
# kubelet binary, static pod manifests (pod CIDR 10.244.0.0/16, service CIDR
# 10.96.0.0/12), etcd data, and a cni0 bridge created at boot.
# =============================================================================
set -eux
. /etc/os-release
case $ID in
    debian|ubuntu)
        apt-get update
        apt-get install -y --no-install-recommends docker.io iptables
        systemctl enable docker.service containerd.service
        apt-get clean
        rm -rf /var/lib/apt/lists/*
        ;;
    *)
        dnf -y -q install podman iproute
        systemctl enable podman.socket
        # kubeadm/k3s on EL are commonly installed with SELinux permissive.
        printf 'SELINUX=permissive\nSELINUXTYPE=targeted\n' >/etc/selinux/config
        dnf clean all
        ;;
esac

cat >/usr/local/bin/kubelet <<'EOF'
#!/bin/sh
# CI stub of kubelet (detection only).
echo "Kubernetes v1.34.0"
EOF
chmod 0755 /usr/local/bin/kubelet
install -d -m 0755 /etc/kubernetes/manifests /var/lib/kubelet /var/lib/etcd/member/wal
cat >/etc/kubernetes/manifests/kube-apiserver.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --secure-port=6443
    - --service-cluster-ip-range=10.96.0.0/12
    image: registry.k8s.io/kube-apiserver:v1.34.0
    name: kube-apiserver
EOF
cat >/etc/kubernetes/manifests/kube-controller-manager.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-controller-manager
    - --allocate-node-cidrs=true
    - --cluster-cidr=10.244.0.0/16
    image: registry.k8s.io/kube-controller-manager:v1.34.0
    name: kube-controller-manager
EOF
printf 'apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\n' >/var/lib/kubelet/config.yaml
# kubeadm prerequisite the hardening must keep: forwarding on at boot.
printf 'net.ipv4.ip_forward = 1\n' >/etc/sysctl.d/k8s.conf

# The CNI bridge (flannel/bridge plugin) exists while the node runs.
cat >/etc/systemd/system/ci-cni0.service <<'EOF'
[Unit]
Description=CI: create the cni0 bridge a CNI plugin would create
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link show cni0 >/dev/null 2>&1 || ip link add cni0 type bridge; ip addr add 10.244.0.1/24 dev cni0 2>/dev/null || true; ip link set cni0 up'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable ci-cni0.service
