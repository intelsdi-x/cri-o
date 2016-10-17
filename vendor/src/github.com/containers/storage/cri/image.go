package cri

import (
	"github.com/containers/image/copy"
	"github.com/containers/image/signature"
	istorage "github.com/containers/image/storage"
	"github.com/containers/image/transports"
	"github.com/containers/image/types"
	"github.com/containers/storage/storage"
	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

type imageService struct {
	store            storage.Store
	defaultTransport string
}

func stringPointer(s string) *string {
	return &s
}

func (svc *imageService) ListImages(ctx context.Context, request *runtime.ListImagesRequest) (*runtime.ListImagesResponse, error) {
	filter := request.GetFilter()
	images, err := svc.store.Images()
	if err != nil {
		return nil, err
	}
	response := runtime.ListImagesResponse{}
	for _, image := range images {
		if filter != nil {
			fimage := filter.GetImage()
			if fimage != nil {
				name := fimage.GetImage()
				if !matchesNameOrID(name, image.ID, image.Names) {
					continue
				}
			}
		}
		// TODO: if image.Names is nil, and we have no RepoTags, it's a
		// violation since the field isn't optional, and we'll fail to
		// hand info about this image back to the client.
		response.Images = append(response.Images, &runtime.Image{
			Id:       stringPointer(image.ID),
			RepoTags: image.Names,
		})
	}
	return &response, nil
}

func (svc *imageService) ImageStatus(ctx context.Context, request *runtime.ImageStatusRequest) (*runtime.ImageStatusResponse, error) {
	image, err := svc.store.GetImage(request.GetImage().GetImage())
	if err != nil {
		return nil, err
	}

	ref, err := istorage.Transport.ParseStoreReference(svc.store, "@"+image.ID)
	if err != nil {
		return nil, err
	}

	systemContext := types.SystemContext{}
	img, err := ref.NewImage(&systemContext)

	response := runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:       stringPointer(image.ID),
			RepoTags: image.Names,
			Size_:    imageSize(img),
		},
	}

	return &response, nil
}

func imageSize(img types.Image) *uint64 {
	var sum int64
	layerInfos := img.LayerInfos()
	info := img.ConfigInfo()
	if info.Size != -1 {
		sum = info.Size
	}
	for _, info := range layerInfos {
		if info.Size == -1 {
			sum = -1
			break
		}
		sum += info.Size
	}
	if len(layerInfos) > 0 && sum >= 0 {
		sum_ := uint64(sum)
		return &sum_
	}
	return nil
}

func (svc *imageService) PullImageUsingContexts(ctx context.Context, imageName string, systemContext *types.SystemContext, policyContext *signature.PolicyContext, options *copy.Options) error {
	if imageName == "" {
		return storage.ErrNotAnImage
	}
	srcRef, err := transports.ParseImageName(imageName)
	if err != nil {
		srcRef2, err2 := transports.ParseImageName(svc.defaultTransport + imageName)
		if err2 != nil {
			return err
		}
		srcRef = srcRef2
	}
	dest := imageName
	if srcRef.DockerReference() != nil {
		dest = srcRef.DockerReference().FullName()
	}
	destRef, err := istorage.Transport.ParseStoreReference(svc.store, dest)
	if err != nil {
		return err
	}
	err = copy.Image(systemContext, policyContext, destRef, srcRef, options)
	if err != nil {
		return err
	}
	// Go find the image, and attach the requested name to it, so that we
	// can more easily find it later, even if the destination reference
	// looks different.
	destImage, err := istorage.Transport.GetStoreImage(svc.store, destRef)
	if err != nil {
		return err
	}
	names := append(destImage.Names, imageName, dest)
	err = svc.store.SetNames(destImage.ID, names)
	if err != nil {
		return err
	}
	return nil
}

func (svc *imageService) PullImage(ctx context.Context, request *runtime.PullImageRequest) (*runtime.PullImageResponse, error) {
	imageName := request.GetImage().GetImage()
	if imageName == "" {
		return nil, storage.ErrNotAnImage
	}
	systemContext := types.SystemContext{}
	policy, err := signature.DefaultPolicy(&systemContext)
	if err != nil {
		return nil, err
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return nil, err
	}
	options := copy.Options{}
	err = svc.PullImageUsingContexts(ctx, imageName, &systemContext, policyContext, &options)
	if err != nil {
		return nil, err
	}
	return &runtime.PullImageResponse{}, nil
}

func (svc *imageService) RemoveImage(ctx context.Context, request *runtime.RemoveImageRequest) (*runtime.RemoveImageResponse, error) {
	image, err := svc.store.GetImage(request.GetImage().GetImage())
	if err != nil {
		return nil, err
	}
	_, err = svc.store.DeleteImage(image.ID, true)
	if err != nil {
		return nil, err
	}
	response := runtime.RemoveImageResponse{}
	return &response, nil
}

func GetStorageImageService(store storage.Store, defaultTransport string) (*imageService, error) {
	if store == nil {
		var err error
		store, err = storage.GetStore(storage.DefaultStoreOptions)
		if err != nil {
			return nil, err
		}
	}
	return &imageService{
		store:            store,
		defaultTransport: defaultTransport,
	}, nil
}
