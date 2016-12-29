package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/registrar"
	"github.com/docker/docker/pkg/truncindex"
	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/kubernetes-incubator/cri-o/server/apparmor"
	"github.com/kubernetes-incubator/cri-o/server/seccomp"
	"github.com/opencontainers/runc/libcontainer/label"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rajatchopra/ocicni"
	pb "k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
	"src/k8s.io/kubernetes/pkg/kubelet/server/streaming"
)

const (
	runtimeAPIVersion = "v1alpha1"
)

type streamService struct {
	runtimeServer *Server
	streamServer  streaming.Server
	streaming.Runtime
}

// Server implements the RuntimeService and ImageService
type Server struct {
	config       Config
	runtime      *oci.Runtime
	stateLock    sync.Mutex
	state        *serverState
	netPlugin    ocicni.CNIPlugin
	podNameIndex *registrar.Registrar
	podIDIndex   *truncindex.TruncIndex
	ctrNameIndex *registrar.Registrar
	ctrIDIndex   *truncindex.TruncIndex

	seccompEnabled bool
	seccompProfile seccomp.Seccomp

	appArmorEnabled bool
	appArmorProfile string

	stream streamService
}

// GetExec returns exec stream request
func (s *Server) GetExec(req *pb.ExecRequest) (*pb.ExecResponse, error) {
	return s.stream.streamServer.GetExec(req)
}

// GetAttach returns attach stream request
func (s *Server) GetAttach(req *pb.AttachRequest) (*pb.AttachResponse, error) {
	return s.stream.streamServer.GetAttach(req, true)
}

// GetPortForward returns port forward stream request
func (s *Server) GetPortForward(req *pb.PortForwardRequest) (*pb.PortForwardResponse, error) {
	return s.stream.streamServer.GetPortForward(req)
}

func (s *Server) loadContainer(id string) error {
	config, err := ioutil.ReadFile(filepath.Join(s.runtime.ContainerDir(), id, "config.json"))
	if err != nil {
		return err
	}
	var m rspec.Spec
	if err = json.Unmarshal(config, &m); err != nil {
		return err
	}
	labels := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["ocid/labels"]), &labels); err != nil {
		return err
	}
	name := m.Annotations["ocid/name"]
	name, err = s.reserveContainerName(id, name)
	if err != nil {
		return err
	}
	var metadata pb.ContainerMetadata
	if err = json.Unmarshal([]byte(m.Annotations["ocid/metadata"]), &metadata); err != nil {
		return err
	}
	sb := s.getSandbox(m.Annotations["ocid/sandbox_id"])
	if sb == nil {
		logrus.Warnf("could not get sandbox with id %s, skipping", m.Annotations["ocid/sandbox_id"])
		return nil
	}

	var tty bool
	if v := m.Annotations["ocid/tty"]; v == "true" {
		tty = true
	}
	containerPath := filepath.Join(s.runtime.ContainerDir(), id)

	var img *pb.ImageSpec
	image, ok := m.Annotations["ocid/image"]
	if ok {
		img = &pb.ImageSpec{
			Image: &image,
		}
	}

	annotations := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["ocid/annotations"]), &annotations); err != nil {
		return err
	}

	ctr, err := oci.NewContainer(id, name, containerPath, m.Annotations["ocid/log_path"], sb.netNs(), labels, annotations, img, &metadata, sb.id, tty)
	if err != nil {
		return err
	}
	s.addContainer(ctr)
	if err = s.runtime.UpdateStatus(ctr); err != nil {
		logrus.Warnf("error updating status for container %s: %v", ctr.ID(), err)
	}
	if err = s.ctrIDIndex.Add(id); err != nil {
		return err
	}
	return nil
}

func configNetNsPath(spec rspec.Spec) (string, error) {
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type != rspec.NetworkNamespace {
			continue
		}

		if ns.Path == "" {
			return "", fmt.Errorf("empty networking namespace")
		}

		return ns.Path, nil
	}

	return "", fmt.Errorf("missing networking namespace")
}

func (s *Server) loadSandbox(id string) error {
	config, err := ioutil.ReadFile(filepath.Join(s.config.SandboxDir, id, "config.json"))
	if err != nil {
		return err
	}
	var m rspec.Spec
	if err = json.Unmarshal(config, &m); err != nil {
		return err
	}
	labels := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["ocid/labels"]), &labels); err != nil {
		return err
	}
	name := m.Annotations["ocid/name"]
	name, err = s.reservePodName(id, name)
	if err != nil {
		return err
	}
	var metadata pb.PodSandboxMetadata
	if err = json.Unmarshal([]byte(m.Annotations["ocid/metadata"]), &metadata); err != nil {
		return err
	}

	processLabel, mountLabel, err := label.InitLabels(label.DupSecOpt(m.Process.SelinuxLabel))
	if err != nil {
		return err
	}

	annotations := make(map[string]string)
	if err = json.Unmarshal([]byte(m.Annotations["ocid/annotations"]), &annotations); err != nil {
		return err
	}

	sb := &sandbox{
		id:           id,
		name:         name,
		logDir:       m.Annotations["ocid/log_path"],
		labels:       labels,
		containers:   oci.NewMemoryStore(),
		processLabel: processLabel,
		mountLabel:   mountLabel,
		annotations:  annotations,
		metadata:     &metadata,
		shmPath:      m.Annotations["ocid/shm_path"],
	}

	// We add a netNS only if we can load a permanent one.
	// Otherwise, the sandbox will live in the host namespace.
	netNsPath, err := configNetNsPath(m)
	if err == nil {
		netNS, nsErr := netNsGet(netNsPath, sb.name)
		// If we can't load the networking namespace
		// because it's closed, we just set the sb netns
		// pointer to nil. Otherwise we return an error.
		if nsErr != nil && nsErr != errSandboxClosedNetNS {
			return nsErr
		}

		sb.netns = netNS
	}

	s.addSandbox(sb)

	sandboxPath := filepath.Join(s.config.SandboxDir, id)

	if err = label.ReserveLabel(processLabel); err != nil {
		return err
	}

	cname, err := s.reserveContainerName(m.Annotations["ocid/container_id"], m.Annotations["ocid/container_name"])
	if err != nil {
		return err
	}
	scontainer, err := oci.NewContainer(m.Annotations["ocid/container_id"], cname, sandboxPath, sandboxPath, sb.netNs(), labels, annotations, nil, nil, id, false)
	if err != nil {
		return err
	}
	sb.infraContainer = scontainer
	if err = s.runtime.UpdateStatus(scontainer); err != nil {
		logrus.Warnf("error updating status for container %s: %v", scontainer.ID(), err)
	}
	if err = s.ctrIDIndex.Add(scontainer.ID()); err != nil {
		return err
	}
	if err = s.podIDIndex.Add(id); err != nil {
		return err
	}
	return nil
}

func (s *Server) restore() {
	sandboxDir, err := ioutil.ReadDir(s.config.SandboxDir)
	if err != nil && !os.IsNotExist(err) {
		logrus.Warnf("could not read sandbox directory %s: %v", sandboxDir, err)
	}
	for _, v := range sandboxDir {
		if !v.IsDir() {
			continue
		}
		if err = s.loadSandbox(v.Name()); err != nil {
			logrus.Warnf("could not restore sandbox %s: %v", v.Name(), err)
		}
	}
	containerDir, err := ioutil.ReadDir(s.runtime.ContainerDir())
	if err != nil && !os.IsNotExist(err) {
		logrus.Warnf("could not read container directory %s: %v", s.runtime.ContainerDir(), err)
	}
	for _, v := range containerDir {
		if !v.IsDir() {
			continue
		}
		if err := s.loadContainer(v.Name()); err != nil {
			logrus.Warnf("could not restore container %s: %v", v.Name(), err)

		}
	}
}

func (s *Server) reservePodName(id, name string) (string, error) {
	if err := s.podNameIndex.Reserve(name, id); err != nil {
		if err == registrar.ErrNameReserved {
			id, err := s.podNameIndex.Get(name)
			if err != nil {
				logrus.Warnf("conflict, pod name %q already reserved", name)
				return "", err
			}
			return "", fmt.Errorf("conflict, name %q already reserved for pod %q", name, id)
		}
		return "", fmt.Errorf("error reserving pod name %q", name)
	}
	return name, nil
}

func (s *Server) releasePodName(name string) {
	s.podNameIndex.Release(name)
}

func (s *Server) reserveContainerName(id, name string) (string, error) {
	if err := s.ctrNameIndex.Reserve(name, id); err != nil {
		if err == registrar.ErrNameReserved {
			id, err := s.ctrNameIndex.Get(name)
			if err != nil {
				logrus.Warnf("conflict, ctr name %q already reserved", name)
				return "", err
			}
			return "", fmt.Errorf("conflict, name %q already reserved for ctr %q", name, id)
		}
		return "", fmt.Errorf("error reserving ctr name %s", name)
	}
	return name, nil
}

func (s *Server) releaseContainerName(name string) {
	s.ctrNameIndex.Release(name)
}

const (
	// SeccompModeFilter refers to the syscall argument SECCOMP_MODE_FILTER.
	SeccompModeFilter = uintptr(2)
)

func seccompEnabled() bool {
	var enabled bool
	// Check if Seccomp is supported, via CONFIG_SECCOMP.
	if _, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_SECCOMP, 0, 0); err != syscall.EINVAL {
		// Make sure the kernel has CONFIG_SECCOMP_FILTER.
		if _, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_SECCOMP, SeccompModeFilter, 0); err != syscall.EINVAL {
			enabled = true
		}
	}
	return enabled
}

// New creates a new Server with options provided
func New(config *Config) (*Server, error) {
	if err := os.MkdirAll(config.ImageDir, 0755); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(config.SandboxDir, 0755); err != nil {
		return nil, err
	}

	r, err := oci.New(config.Runtime, config.ContainerDir, config.Conmon, config.ConmonEnv, config.CgroupManager)
	if err != nil {
		return nil, err
	}
	sandboxes := make(map[string]*sandbox)
	containers := oci.NewMemoryStore()
	netPlugin, err := ocicni.InitCNI(config.NetworkDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		runtime:   r,
		netPlugin: netPlugin,
		config:    *config,
		state: &serverState{
			sandboxes:  sandboxes,
			containers: containers,
		},
		seccompEnabled:  seccompEnabled(),
		appArmorEnabled: apparmor.IsEnabled(),
		appArmorProfile: config.ApparmorProfile,
	}
	seccompProfile, err := ioutil.ReadFile(config.SeccompProfile)
	if err != nil {
		return nil, fmt.Errorf("opening seccomp profile (%s) failed: %v", config.SeccompProfile, err)
	}
	var seccompConfig seccomp.Seccomp
	if err := json.Unmarshal(seccompProfile, &seccompConfig); err != nil {
		return nil, fmt.Errorf("decoding seccomp profile failed: %v", err)
	}
	s.seccompProfile = seccompConfig

	if s.appArmorEnabled && s.appArmorProfile == apparmor.DefaultApparmorProfile {
		if err := apparmor.EnsureDefaultApparmorProfile(); err != nil {
			return nil, fmt.Errorf("ensuring the default apparmor profile is installed failed: %v", err)
		}
	}

	s.podIDIndex = truncindex.NewTruncIndex([]string{})
	s.podNameIndex = registrar.NewRegistrar()
	s.ctrIDIndex = truncindex.NewTruncIndex([]string{})
	s.ctrNameIndex = registrar.NewRegistrar()

	s.restore()

	streamServerConfig := streaming.DefaultConfig
	streamServerConfig.Addr = "0.0.0.0:10101"
	s.stream.runtimeServer = s
	s.stream.streamServer, err = streaming.NewServer(streamServerConfig, s.stream)
	if err != nil {
		return nil, fmt.Errorf("unable to create streaming server")
	}

	// TODO: Is it should be started somewhere else?
	go func() {
		s.stream.streamServer.Start(true)
	}()

	logrus.Debugf("sandboxes: %v", s.state.sandboxes)
	logrus.Debugf("containers: %v", s.state.containers)
	return s, nil
}

type serverState struct {
	sandboxes  map[string]*sandbox
	containers oci.Store
}

func (s *Server) addSandbox(sb *sandbox) {
	s.stateLock.Lock()
	s.state.sandboxes[sb.id] = sb
	s.stateLock.Unlock()
}

func (s *Server) getSandbox(id string) *sandbox {
	s.stateLock.Lock()
	sb := s.state.sandboxes[id]
	s.stateLock.Unlock()
	return sb
}

func (s *Server) hasSandbox(id string) bool {
	s.stateLock.Lock()
	_, ok := s.state.sandboxes[id]
	s.stateLock.Unlock()
	return ok
}

func (s *Server) removeSandbox(id string) {
	s.stateLock.Lock()
	delete(s.state.sandboxes, id)
	s.stateLock.Unlock()
}

func (s *Server) addContainer(c *oci.Container) {
	s.stateLock.Lock()
	sandbox := s.state.sandboxes[c.Sandbox()]
	// TODO(runcom): handle !ok above!!! otherwise it panics!
	sandbox.addContainer(c)
	s.state.containers.Add(c.ID(), c)
	s.stateLock.Unlock()
}

func (s *Server) getContainer(id string) *oci.Container {
	s.stateLock.Lock()
	c := s.state.containers.Get(id)
	s.stateLock.Unlock()
	return c
}

func (s *Server) removeContainer(c *oci.Container) {
	s.stateLock.Lock()
	sandbox := s.state.sandboxes[c.Sandbox()]
	sandbox.removeContainer(c)
	s.state.containers.Delete(c.ID())
	s.stateLock.Unlock()
}
