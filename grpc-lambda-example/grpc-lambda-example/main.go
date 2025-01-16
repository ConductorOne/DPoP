package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	pb_connector_manager "github.com/ductone/c1-lambda/pb/c1/svc/connector_manager/v1"
	pbexample "github.com/ductone/c1-lambda/pb/example/v1"
	c1_lambda_grpc "github.com/ductone/c1-lambda/pkg/grpc"
)

func handler(config *pb_connector_manager.GetConnectorConfigResponse) *c1_lambda_grpc.Server {
	s := c1_lambda_grpc.NewServer(nil)
	srv := &ExampleServer{}
	pbexample.RegisterExampleServer(s, srv)
	return s
}

// Required env
// C1_CONNECTOR_MANAGER_HOST
// C1_TENANT_ID
// C1_APP_ID
// C1_CONNECTOR_ID
func main() {
	//ctx := context.Background()
	//tenantID, ok := os.LookupEnv("C1_TENANT_ID")
	//if !ok {
	//	panic("C1_TENANT_ID is required")
	//}
	//appID, ok := os.LookupEnv("C1_APP_ID")
	//if !ok {
	//	panic("C1_APP_ID is required")
	//}
	//connectorID, ok := os.LookupEnv("C1_CONNECTOR_ID")
	//if !ok {
	//	panic("C1_CONNECTOR_ID is required")
	//}
	//connectorManagerHost, ok := os.LookupEnv("C1_CONNECTOR_MANAGER_HOST")
	//if !ok {
	//	panic("C1_CONNECTOR_MANAGER_HOST is required")
	//}
	//
	//config, err := config.GetConnectorConfig(ctx, tenantID, appID, connectorID, connectorManagerHost)
	//if err != nil {
	//	panic("failed to get connector config: " + err.Error())
	//}
	lambda.Start(handler(nil).Handler)
}
