# Running cri-o on kubernetes cluster

## Switching runtime to cri-o
Having working setup with cri-o 

| File path                            | Description                |
|--------------------------------------|----------------------------|
| `/etc/ocid/ocid.conf`                | ocid configuration         |
| /`etc/ocid/seccomp.conf`             | seccomp configuration      |
| `/etc/containers/policy.json`        | container policy           |
| `/bin/{ocid, runc}`                  | `ocid` and `runc` binaries |
| `/opt/cni/bin/{flannel, bridge,...}` | CNI plugins                |
| `/usr/libexec/ocid/conmon`           | `conmon` binary            |
|                                      |                            |