# Running cri-o on kubernetes cluster

## Switching runtime from docker to cri-o

In standard docker kubernetes cluster, kubelet is running on each node, as systemd service and is taking care of communication between runtime and api service. 
It is reponsible for starting microservices pods (such as `kube-proxy`, `kubedns`, etc. - they can be different for various ways of deploying k8s) and user pods.
Configuration of kubelet determines what runtime is used and in what way. 

Kubelet itself is executed in docker container (as we can see in `kubelet.service`), but, what is important, **it's not** a kubernetes pod (at least for now), 
so we can keep kubelet running inside docker container (as well as in another way), and regardless of this, run pods in chosen runtime.

Below, you can find an instruction how to switch one or more nodes on running kubernetes cluster from docker to cri-o.  

### Preparing ocid 

We must prepare and install `ocid` on each node we would switch. Here's the list of files we must provide:

| File path                            | Description                | Location                                            |
|--------------------------------------|----------------------------|-----------------------------------------------------|
| `/etc/ocid/ocid.conf`                | ocid configuration         | Generated on cri-o `make install`                   |
| `/etc/ocid/seccomp.conf`             | seccomp config             | Example stored in cri-o repository                  |
| `/etc/containers/policy.json`        | containers policy          | Example stored in cri-o repository                  |
| `/bin/{ocid, runc}`                  | `ocid` and `runc` binaries | Built from cri-o repository                         |
| `/usr/libexec/ocid/conmon`           | `conmon` binary            | Built from cri-o repository                         |
| `/opt/cni/bin/{flannel, bridge,...}` | CNI plugins binaries       | Can be built from sources `containernetworking/cni` |

`ocid` binary can be running directly on host, inside the container or in any way.
If you would like to set it as a systemd service, here's the example of unit file:

```
# cat /etc/systemd/system/ocid.service 
[Unit]
Description=CRI-O daemon
Documentation=https://github.com/kubernetes-incubator/cri-o

[Service]
ExecStart=/bin/ocid --runtime /bin/runc --log /root/ocid.log --debug
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

### Preparing kubelet
At first, you need to stop kubelet service working on the node:
```
# systemctl stop kubelet
```
and stop all kubelet docker containers that are still runing.

```
# docker stop $(docker ps | grep k8s_ | awk '{print $1}')
```

Kubelet parameters are stored in `/etc/kubernetes/kubelet.env` file.
```
# cat /etc/kubernetes/kubelet.env | grep KUBELET_ARGS
KUBELET_ARGS="--pod-manifest-path=/etc/kubernetes/manifests 
--pod-infra-container-image=gcr.io/google_containers/pause-amd64:3.0 
--cluster_dns=10.233.0.3 --cluster_domain=cluster.local 
--resolv-conf=/etc/resolv.conf --kubeconfig=/etc/kubernetes/node-kubeconfig.yaml
--require-kubeconfig"
```

