package server

import (
	"github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	pb "k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

// ListImages lists existing images.
func (s *Server) ListImages(ctx context.Context, req *pb.ListImagesRequest) (*pb.ListImagesResponse, error) {
	logrus.Debugf("ListImages: %+v", req)
	return s.images.ListImages(ctx, req)
}

// ImageStatus returns the status of the image.
func (s *Server) ImageStatus(ctx context.Context, req *pb.ImageStatusRequest) (*pb.ImageStatusResponse, error) {
	logrus.Debugf("ImageStatus: %+v", req)
	return s.images.ImageStatus(ctx, req)
}

// PullImage pulls a image with authentication config.
func (s *Server) PullImage(ctx context.Context, req *pb.PullImageRequest) (*pb.PullImageResponse, error) {
	logrus.Debugf("PullImage: %+v", req)
	// TODO(runcom?): deal with AuthConfig in req.GetAuth()
	// TODO(somebody?): either rework PullImage to verify signatures, or do it by using PullImageUsingContexts, if that's enough
	// TODO: what else do we need here? (Signatures when the story isn't just pulling from docker://)
	return s.images.PullImage(ctx, req)
}

// RemoveImage removes the image.
func (s *Server) RemoveImage(ctx context.Context, req *pb.RemoveImageRequest) (*pb.RemoveImageResponse, error) {
	logrus.Debugf("RemoveImage: %+v", req)
	return s.images.RemoveImage(ctx, req)
}
