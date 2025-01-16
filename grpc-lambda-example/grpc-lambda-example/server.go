package main

import (
	"context"

	pbexample "github.com/ductone/c1-lambda/pb/example/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ExampleServer struct{}

func (e *ExampleServer) Hello(ctx context.Context, h *pbexample.HelloRequest) (*pbexample.HelloResponse, error) {
	if h.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}

	// Echo back any headers or trailers
	md, _ := metadata.FromIncomingContext(ctx)
	for k, v := range md {
		for _, vv := range v {
			switch k {
			case "x-echo-header":
				_ = grpc.SetHeader(ctx, metadata.Pairs("x-echo-header-resp", vv))
			case "x-echo-trailer":
				_ = grpc.SetTrailer(ctx, metadata.Pairs("x-echo-trailer-resp", vv))
			}
		}
	}

	return &pbexample.HelloResponse{
		Msg: "Hello " + h.Name,
	}, nil
}
