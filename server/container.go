package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/containers/storage/cri"
	"github.com/docker/docker/pkg/stringid"
	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/opencontainers/runtime-tools/generate"
	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/fields"
	pb "k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

func (s *Server) generateContainerIDandName(podName string, name string, attempt uint32) (string, string, error) {
	var (
		err error
		id  = stringid.GenerateNonCryptoID()
	)
	nameStr := fmt.Sprintf("%s-%s-%v", podName, name, attempt)
	if name == "infra" {
		nameStr = fmt.Sprintf("%s-%s", podName, name)
	}
	if name, err = s.reserveContainerName(id, nameStr); err != nil {
		return "", "", err
	}
	return id, name, err
}

type containerRequest interface {
	GetContainerId() string
}

func (s *Server) getContainerFromRequest(req containerRequest) (*oci.Container, error) {
	ctrID := req.GetContainerId()
	if ctrID == "" {
		return nil, fmt.Errorf("container ID should not be empty")
	}

	containerID, err := s.ctrIDIndex.Get(ctrID)
	if err != nil {
		return nil, fmt.Errorf("container with ID starting with %s not found: %v", ctrID, err)
	}

	c := s.state.containers.Get(containerID)
	if c == nil {
		return nil, fmt.Errorf("specified container not found: %s", containerID)
	}
	return c, nil
}

// CreateContainer creates a new container in specified PodSandbox
func (s *Server) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (res *pb.CreateContainerResponse, err error) {
	logrus.Debugf("CreateContainerRequest %+v", req)
	sbID := req.GetPodSandboxId()
	if sbID == "" {
		return nil, fmt.Errorf("PodSandboxId should not be empty")
	}

	sandboxID, err := s.podIDIndex.Get(sbID)
	if err != nil {
		return nil, fmt.Errorf("PodSandbox with ID starting with %s not found: %v", sbID, err)
	}

	sb := s.getSandbox(sandboxID)
	if sb == nil {
		return nil, fmt.Errorf("specified sandbox not found: %s", sandboxID)
	}

	// The config of the container
	containerConfig := req.GetConfig()
	if containerConfig == nil {
		return nil, fmt.Errorf("CreateContainerRequest.ContainerConfig is nil")
	}

	name := containerConfig.GetMetadata().GetName()
	if name == "" {
		return nil, fmt.Errorf("CreateContainerRequest.ContainerConfig.Name is empty")
	}

	attempt := containerConfig.GetMetadata().GetAttempt()
	containerID, containerName, err := s.generateContainerIDandName(sb.name, name, attempt)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			s.releaseContainerName(containerName)
			err1 := s.storage.DeleteContainer(containerID)
			if err1 != nil {
				logrus.Warnf("Failed to cleanup container directory: %v")
			}
		}
	}()

	container, err := s.createSandboxContainer(ctx, containerID, containerName, sb, req.GetSandboxConfig(), containerConfig)
	if err != nil {
		return nil, err
	}

	if err = s.runtime.CreateContainer(container); err != nil {
		return nil, err
	}

	if err = s.runtime.UpdateStatus(container); err != nil {
		return nil, err
	}

	s.addContainer(container)

	if err = s.ctrIDIndex.Add(containerID); err != nil {
		s.removeContainer(container)
		return nil, err
	}

	resp := &pb.CreateContainerResponse{
		ContainerId: &containerID,
	}

	logrus.Debugf("CreateContainerResponse: %+v", resp)
	return resp, nil
}

func (s *Server) createSandboxContainer(ctx context.Context, containerID string, containerName string, sb *sandbox, SandboxConfig *pb.PodSandboxConfig, containerConfig *pb.ContainerConfig) (*oci.Container, error) {
	if sb == nil {
		return nil, errors.New("createSandboxContainer needs a sandbox")
	}

	// TODO: factor generating/updating the spec into something other projects can vendor

	// creates a spec Generator with the default spec.
	specgen := generate.New()

	args := containerConfig.GetArgs()
	if args == nil {
		args = []string{"/bin/sh"}
	}
	specgen.SetProcessArgs(args)

	cwd := containerConfig.GetWorkingDir()
	if cwd == "" {
		cwd = "/"
	}
	specgen.SetProcessCwd(cwd)

	envs := containerConfig.GetEnvs()
	if envs != nil {
		for _, item := range envs {
			key := item.GetKey()
			value := item.GetValue()
			if key == "" {
				continue
			}
			env := fmt.Sprintf("%s=%s", key, value)
			specgen.AddProcessEnv(env)
		}
	}

	mounts := containerConfig.GetMounts()
	for _, mount := range mounts {
		dest := mount.GetContainerPath()
		if dest == "" {
			return nil, fmt.Errorf("Mount.ContainerPath is empty")
		}

		src := mount.GetHostPath()
		if src == "" {
			return nil, fmt.Errorf("Mount.HostPath is empty")
		}

		options := "rw"
		if mount.GetReadonly() {
			options = "ro"
		}

		if mount.GetSelinuxRelabel() {
			// Need a way in kubernetes to determine if the volume is shared or private
			if err := label.Relabel(src, sb.mountLabel, true); err != nil && err != syscall.ENOTSUP {
				return nil, fmt.Errorf("relabel failed %s: %v", src, err)
			}
		}

		specgen.AddBindMount(src, dest, options)

	}

	labels := containerConfig.GetLabels()

	metadata := containerConfig.GetMetadata()

	annotations := containerConfig.GetAnnotations()
	if annotations != nil {
		for k, v := range annotations {
			specgen.AddAnnotation(k, v)
		}
	}
	if containerConfig.GetLinux().GetSecurityContext().GetPrivileged() {
		specgen.SetupPrivileged(true)
	}

	if containerConfig.GetLinux().GetSecurityContext().GetReadonlyRootfs() {
		specgen.SetRootReadonly(true)
	}

	logPath := containerConfig.GetLogPath()

	if containerConfig.GetTty() {
		specgen.SetProcessTerminal(true)
	}

	linux := containerConfig.GetLinux()
	if linux != nil {
		resources := linux.GetResources()
		if resources != nil {
			cpuPeriod := resources.GetCpuPeriod()
			if cpuPeriod != 0 {
				specgen.SetLinuxResourcesCPUPeriod(uint64(cpuPeriod))
			}

			cpuQuota := resources.GetCpuQuota()
			if cpuQuota != 0 {
				specgen.SetLinuxResourcesCPUQuota(uint64(cpuQuota))
			}

			cpuShares := resources.GetCpuShares()
			if cpuShares != 0 {
				specgen.SetLinuxResourcesCPUShares(uint64(cpuShares))
			}

			memoryLimit := resources.GetMemoryLimitInBytes()
			if memoryLimit != 0 {
				specgen.SetLinuxResourcesMemoryLimit(uint64(memoryLimit))
			}

			oomScoreAdj := resources.GetOomScoreAdj()
			specgen.SetLinuxResourcesOOMScoreAdj(int(oomScoreAdj))
		}

		capabilities := linux.GetSecurityContext().GetCapabilities()
		if capabilities != nil {
			addCaps := capabilities.GetAddCapabilities()
			if addCaps != nil {
				for _, cap := range addCaps {
					if err := specgen.AddProcessCapability(cap); err != nil {
						return nil, err
					}
				}
			}

			dropCaps := capabilities.GetDropCapabilities()
			if dropCaps != nil {
				for _, cap := range dropCaps {
					if err := specgen.DropProcessCapability(cap); err != nil {
						return nil, err
					}
				}
			}
		}

		specgen.SetProcessSelinuxLabel(sb.processLabel)
		specgen.SetLinuxMountLabel(sb.mountLabel)

		user := linux.GetSecurityContext().GetRunAsUser()
		specgen.SetProcessUID(uint32(user))

		specgen.SetProcessGID(uint32(user))

		groups := linux.GetSecurityContext().GetSupplementalGroups()
		for _, group := range groups {
			specgen.AddProcessAdditionalGid(uint32(group))
		}
	}
	// Join the namespace paths for the pod sandbox container.
	podInfraState := s.runtime.ContainerStatus(sb.infraContainer)

	logrus.Debugf("pod container state %+v", podInfraState)

	for nsType, nsFile := range map[string]string{
		"ipc":     "ipc",
		"network": "net",
	} {
		nsPath := fmt.Sprintf("/proc/%d/ns/%s", podInfraState.Pid, nsFile)
		if err := specgen.AddOrReplaceLinuxNamespace(nsType, nsPath); err != nil {
			return nil, err
		}
	}

	specgen.AddAnnotation("ocid/name", containerName)
	specgen.AddAnnotation("ocid/sandbox_id", sb.id)
	specgen.AddAnnotation("ocid/log_path", logPath)
	specgen.AddAnnotation("ocid/tty", fmt.Sprintf("%v", containerConfig.GetTty()))

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	specgen.AddAnnotation("ocid/metadata", string(metadataJSON))

	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	specgen.AddAnnotation("ocid/labels", string(labelsJSON))

	imageSpec := containerConfig.GetImage()
	if imageSpec == nil {
		return nil, fmt.Errorf("CreateContainerRequest.ContainerConfig.Image is nil")
	}

	image := imageSpec.GetImage()
	if image == "" {
		return nil, fmt.Errorf("CreateContainerRequest.ContainerConfig.Image.Image is empty")
	}

	storageMetadata := cri.StorageRuntimeContainerMetadata{
		Pod:           false,
		PodName:       sb.name,
		PodID:         sb.id,
		ImageName:     image,
		ContainerName: containerName,
		MetadataName:  containerConfig.GetMetadata().GetName(),
		Attempt:       containerConfig.GetMetadata().GetAttempt(),
		MountLabel:    sb.mountLabel,
	}
	containerInfo, err := s.storage.CreateContainer(ctx, storageMetadata, containerID)
	if err != nil {
		return nil, err
	}

	mountPoint, err := s.storage.StartContainer(containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to mount container %s(%s): %v", containerName, containerID, err)
	}

	// by default, the root path is an empty string. set it now.
	specgen.SetRootPath(mountPoint)

	saveOptions := generate.ExportOptions{}
	if err = specgen.SaveToFile(filepath.Join(containerInfo.Dir, "config.json"), saveOptions); err != nil {
		return nil, err
	}
	if err = specgen.SaveToFile(filepath.Join(containerInfo.RunDir, "config.json"), saveOptions); err != nil {
		return nil, err
	}

	container, err := oci.NewContainer(containerID, containerName, containerInfo.RunDir, logPath, labels, metadata, sb.id, containerConfig.GetTty())
	if err != nil {
		return nil, err
	}

	return container, nil
}

// StartContainer starts the container.
func (s *Server) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.StartContainerResponse, error) {
	logrus.Debugf("StartContainerRequest %+v", req)
	c, err := s.getContainerFromRequest(req)
	if err != nil {
		return nil, err
	}

	workdir, err := s.storage.GetWorkDir(c.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to find work directory for container %s(%s): %v", c.Name(), c.ID(), err)
	}
	rundir, err := s.storage.GetRunDir(c.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to find runtime directory for container %s(%s): %v", c.Name(), c.ID(), err)
	}
	mountPoint, err := s.storage.StartContainer(c.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to mount container %s(%s): %v", c.Name(), c.ID(), err)
	}
	specgen, err := generate.NewFromFile(filepath.Join(workdir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read template configuration for container: %v", err)
	}
	specgen.SetRootPath(mountPoint)
	saveOptions := generate.ExportOptions{}
	if err = specgen.SaveToFile(filepath.Join(workdir, "config.json"), saveOptions); err != nil {
		return nil, fmt.Errorf("failed to rewrite template configuration for container: %v", err)
	}
	if err = specgen.SaveToFile(filepath.Join(rundir, "config.json"), saveOptions); err != nil {
		return nil, fmt.Errorf("failed to write runtime configuration for container: %v", err)
	}

	if err = s.runtime.StartContainer(c); err != nil {
		return nil, fmt.Errorf("failed to start container %s(%s): %v", c.Name(), c.ID(), err)
	}

	resp := &pb.StartContainerResponse{}
	logrus.Debugf("StartContainerResponse %+v", resp)
	return resp, nil
}

// StopContainer stops a running container with a grace period (i.e., timeout).
func (s *Server) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	logrus.Debugf("StopContainerRequest %+v", req)
	c, err := s.getContainerFromRequest(req)
	if err != nil {
		return nil, err
	}

	if err := s.runtime.StopContainer(c); err != nil {
		return nil, fmt.Errorf("failed to stop container %s: %v", c.ID(), err)
	}

	if err := s.storage.StopContainer(c.ID()); err != nil {
		return nil, fmt.Errorf("failed to unmount container %s: %v", c.ID(), err)
	}

	resp := &pb.StopContainerResponse{}
	logrus.Debugf("StopContainerResponse: %+v", resp)
	return resp, nil
}

// RemoveContainer removes the container. If the container is running, the container
// should be force removed.
func (s *Server) RemoveContainer(ctx context.Context, req *pb.RemoveContainerRequest) (*pb.RemoveContainerResponse, error) {
	logrus.Debugf("RemoveContainerRequest %+v", req)
	c, err := s.getContainerFromRequest(req)
	if err != nil {
		return nil, err
	}

	if err := s.runtime.UpdateStatus(c); err != nil {
		return nil, fmt.Errorf("failed to update container state: %v", err)
	}

	cState := s.runtime.ContainerStatus(c)
	if cState.Status == oci.ContainerStateCreated || cState.Status == oci.ContainerStateRunning {
		if err := s.runtime.StopContainer(c); err != nil {
			return nil, fmt.Errorf("failed to stop container %s: %v", c.ID(), err)
		}
	}

	if err := s.runtime.DeleteContainer(c); err != nil {
		return nil, fmt.Errorf("failed to delete container %s: %v", c.ID(), err)
	}

	if err := s.storage.DeleteContainer(c.ID()); err != nil {
		return nil, fmt.Errorf("failed to delete container %s: %v", c.ID(), err)
	}

	s.releaseContainerName(c.Name())
	s.removeContainer(c)

	if err := s.ctrIDIndex.Delete(c.ID()); err != nil {
		return nil, err
	}

	resp := &pb.RemoveContainerResponse{}
	logrus.Debugf("RemoveContainerResponse: %+v", resp)
	return resp, nil
}

// filterContainer returns whether passed container matches filtering criteria
func filterContainer(c *pb.Container, filter *pb.ContainerFilter) bool {
	if filter != nil {
		if filter.State != nil {
			if *c.State != *filter.State {
				return false
			}
		}
		if filter.LabelSelector != nil {
			sel := fields.SelectorFromSet(filter.LabelSelector)
			if !sel.Matches(fields.Set(c.Labels)) {
				return false
			}
		}
	}
	return true
}

// ListContainers lists all containers by filters.
func (s *Server) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	logrus.Debugf("ListContainersRequest %+v", req)
	var ctrs []*pb.Container
	filter := req.Filter
	ctrList := s.state.containers.List()

	// Filter using container id and pod id first.
	if filter != nil {
		if filter.Id != nil {
			c := s.state.containers.Get(*filter.Id)
			if c != nil {
				if filter.PodSandboxId != nil {
					if c.Sandbox() == *filter.PodSandboxId {
						ctrList = []*oci.Container{c}
					} else {
						ctrList = []*oci.Container{}
					}

				} else {
					ctrList = []*oci.Container{c}
				}
			}
		} else {
			if filter.PodSandboxId != nil {
				pod := s.state.sandboxes[*filter.PodSandboxId]
				if pod == nil {
					ctrList = []*oci.Container{}
				} else {
					ctrList = pod.containers.List()
				}
			}
		}
	}

	for _, ctr := range ctrList {
		if err := s.runtime.UpdateStatus(ctr); err != nil {
			return nil, err
		}

		podSandboxID := ctr.Sandbox()
		cState := s.runtime.ContainerStatus(ctr)
		created := cState.Created.UnixNano()
		rState := pb.ContainerState_CONTAINER_UNKNOWN
		cID := ctr.ID()

		c := &pb.Container{
			Id:           &cID,
			PodSandboxId: &podSandboxID,
			CreatedAt:    int64Ptr(created),
			Labels:       ctr.Labels(),
			Metadata:     ctr.Metadata(),
		}

		switch cState.Status {
		case oci.ContainerStateCreated:
			rState = pb.ContainerState_CONTAINER_CREATED
		case oci.ContainerStateRunning:
			rState = pb.ContainerState_CONTAINER_RUNNING
		case oci.ContainerStateStopped:
			rState = pb.ContainerState_CONTAINER_EXITED
		}
		c.State = &rState

		// Filter by other criteria such as state and labels.
		if filterContainer(c, req.Filter) {
			ctrs = append(ctrs, c)
		}
	}

	resp := &pb.ListContainersResponse{
		Containers: ctrs,
	}
	logrus.Debugf("ListContainersResponse: %+v", resp)
	return resp, nil
}

// ContainerStatus returns status of the container.
func (s *Server) ContainerStatus(ctx context.Context, req *pb.ContainerStatusRequest) (*pb.ContainerStatusResponse, error) {
	logrus.Debugf("ContainerStatusRequest %+v", req)
	c, err := s.getContainerFromRequest(req)
	if err != nil {
		return nil, err
	}

	if err := s.runtime.UpdateStatus(c); err != nil {
		return nil, err
	}

	containerID := c.ID()
	resp := &pb.ContainerStatusResponse{
		Status: &pb.ContainerStatus{
			Id:       &containerID,
			Metadata: c.Metadata(),
		},
	}

	cState := s.runtime.ContainerStatus(c)
	rStatus := pb.ContainerState_CONTAINER_UNKNOWN

	switch cState.Status {
	case oci.ContainerStateCreated:
		rStatus = pb.ContainerState_CONTAINER_CREATED
		created := cState.Created.UnixNano()
		resp.Status.CreatedAt = int64Ptr(created)
	case oci.ContainerStateRunning:
		rStatus = pb.ContainerState_CONTAINER_RUNNING
		created := cState.Created.UnixNano()
		resp.Status.CreatedAt = int64Ptr(created)
		started := cState.Started.UnixNano()
		resp.Status.StartedAt = int64Ptr(started)
	case oci.ContainerStateStopped:
		rStatus = pb.ContainerState_CONTAINER_EXITED
		created := cState.Created.UnixNano()
		resp.Status.CreatedAt = int64Ptr(created)
		started := cState.Started.UnixNano()
		resp.Status.StartedAt = int64Ptr(started)
		finished := cState.Finished.UnixNano()
		resp.Status.FinishedAt = int64Ptr(finished)
		resp.Status.ExitCode = int32Ptr(cState.ExitCode)
	}

	resp.Status.State = &rStatus

	logrus.Debugf("ContainerStatusResponse: %+v", resp)
	return resp, nil
}

// UpdateRuntimeConfig updates the configuration of a running container.
func (s *Server) UpdateRuntimeConfig(ctx context.Context, req *pb.UpdateRuntimeConfigRequest) (*pb.UpdateRuntimeConfigResponse, error) {
	return nil, nil
}

// ExecSync runs a command in a container synchronously.
func (s *Server) ExecSync(ctx context.Context, req *pb.ExecSyncRequest) (*pb.ExecSyncResponse, error) {
	return nil, nil
}

// Exec prepares a streaming endpoint to execute a command in the container.
func (s *Server) Exec(ctx context.Context, req *pb.ExecRequest) (*pb.ExecResponse, error) {
	return nil, nil
}

// Attach prepares a streaming endpoint to attach to a running container.
func (s *Server) Attach(ctx context.Context, req *pb.AttachRequest) (*pb.AttachResponse, error) {
	return nil, nil
}

// PortForward prepares a streaming endpoint to forward ports from a PodSandbox.
func (s *Server) PortForward(ctx context.Context, req *pb.PortForwardRequest) (*pb.PortForwardResponse, error) {
	return nil, nil
}

// Status returns the status of the runtime
func (s *Server) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	return nil, nil
}
