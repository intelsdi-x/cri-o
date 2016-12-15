package server

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/kubernetes-incubator/cri-o/oci"
	"golang.org/x/net/context"
	pb "k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

// Exec prepares a streaming endpoint to execute a command in the container.
func (s *Server) Exec(ctx context.Context, req *pb.ExecRequest) (*pb.ExecResponse, error) {
	logrus.Debugf("ExecRequest %+v", req)
	c, err := s.getContainerFromRequest(req)
	if err != nil {
		return nil, err
	}

	if err = s.runtime.UpdateStatus(c); err != nil {
		return nil, err
	}

	cState := s.runtime.ContainerStatus(c)
	if !(cState.Status == oci.ContainerStateRunning || cState.Status == oci.ContainerStateCreated) {
		return nil, fmt.Errorf("container is not created or running")
	}

	cmd := req.GetCmd()
	if cmd == nil {
		return nil, fmt.Errorf("exec command cannot be empty")
	}

	resp, err := s.runtime.GetExec(req)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare exec endpoint")
	}

	return resp, nil
}
