package main

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	aws_transport "github.com/aws/smithy-go/endpoints"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pbexample "github.com/ductone/c1-lambda/pb/example/v1"
	c1_lambda_grpc "github.com/ductone/c1-lambda/pkg/grpc"
	"github.com/ductone/c1-lambda/pkg/grpc/transport"
)

type localLambdaResolver struct{}

func (l localLambdaResolver) ResolveEndpoint(ctx context.Context, params lambda.EndpointParameters) (aws_transport.Endpoint, error) {
	uri, err := url.Parse("http://127.0.0.1:3001")
	if err != nil {
		return aws_transport.Endpoint{}, fmt.Errorf("failed to parse url: %v", err)
	}
	return aws_transport.Endpoint{
		URI: *uri,
	}, nil
}

func TestLambdaTransport(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     "fakeAccessKey",
				SecretAccessKey: "fakeSecretAccessKey",
				SessionToken:    "fakeSessionToken",
				Source:          "fake",
				CanExpire:       false,
				AccountID:       "1234567890",
			},
		}),
	)

	lambdaClient := lambda.NewFromConfig(cfg, lambda.WithEndpointResolverV2(&localLambdaResolver{}))

	lt, err := transport.NewLambdaClientTransport(ctx, lambdaClient, "GRPCExampleFunction")
	require.NoError(t, err)
	c := c1_lambda_grpc.NewClientConn(lt)
	client := pbexample.NewExampleClient(c)

	// OK
	headers := &metadata.MD{}
	trailers := &metadata.MD{}
	md := metadata.Pairs("x-echo-header", "header-value", "x-echo-trailer", "trailer-value")
	md.Append("x-echo-header", "header-value-2")
	ctx = metadata.NewOutgoingContext(ctx, md)
	resp, err := client.Hello(ctx, &pbexample.HelloRequest{Name: "Mr. Pink"}, grpc.Header(headers), grpc.Trailer(trailers))
	require.NoError(t, err)
	require.Equal(t, "Hello Mr. Pink", resp.Msg)
	require.Equal(t, headers, &metadata.MD{"x-echo-header-resp": []string{"header-value", "header-value-2"}})
	require.Equal(t, trailers, &metadata.MD{"x-echo-trailer-resp": []string{"trailer-value"}})

	// Invalid Request
	resp, err = client.Hello(ctx, &pbexample.HelloRequest{Name: ""})
	require.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "name is required", st.Message())
}

func TestExampleServerLocalTransport(t *testing.T) {
	ctx := context.Background()
	srv := &ExampleServer{}

	s := c1_lambda_grpc.NewServer(nil)
	pbexample.RegisterExampleServer(s, srv)

	ct := transport.NewLocalClientTransport(s)
	c := c1_lambda_grpc.NewClientConn(ct)
	client := pbexample.NewExampleClient(c)

	headers := &metadata.MD{}
	trailers := &metadata.MD{}
	md := metadata.Pairs("x-echo-header", "header-value", "x-echo-trailer", "trailer-value")
	md.Append("x-echo-header", "header-value-2")
	ctx = metadata.NewOutgoingContext(ctx, md)
	resp, err := client.Hello(ctx, &pbexample.HelloRequest{Name: "Mr. Pink"}, grpc.Header(headers), grpc.Trailer(trailers))
	require.NoError(t, err)
	require.Equal(t, "Hello Mr. Pink", resp.Msg)

	// Invalid Request
	resp, err = client.Hello(ctx, &pbexample.HelloRequest{Name: ""})
	require.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "name is required", st.Message())
}
