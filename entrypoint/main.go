package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/davecgh/go-spew/spew"

	pb_connector_manager "github.com/ductone/c1-lambda/pb/c1/svc/connector_manager/v1"
	"github.com/ductone/c1-lambda/pkg"
)

type handlerFunc func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)

func handler(config *pb_connector_manager.GetConnectorConfigResponse) handlerFunc {
	return func(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		spew.Dump("CURRENT CONFIG: ", config)
		response := events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       "\"Hello from Lambda!\"",
		}
		return response, nil
	}
}

// Required env
// C1_CONNECTOR_MANAGER_HOST
// C1_TENANT_ID
// C1_APP_ID
// C1_CONNECTOR_ID
func main() {
	ctx := context.Background()
	tenantID, ok := os.LookupEnv("C1_TENANT_ID")
	if !ok {
		panic("C1_TENANT_ID is required")
	}
	appID, ok := os.LookupEnv("C1_APP_ID")
	if !ok {
		panic("C1_APP_ID is required")
	}
	connectorID, ok := os.LookupEnv("C1_CONNECTOR_ID")
	if !ok {
		panic("C1_CONNECTOR_ID is required")
	}
	connectorManagerHost, ok := os.LookupEnv("C1_CONNECTOR_MANAGER_HOST")
	if !ok {
		panic("C1_CONNECTOR_MANAGER_HOST is required")
	}

	config, err := pkg.GetConnectorConfig(ctx, tenantID, appID, connectorID, connectorManagerHost)
	if err != nil {
		panic("failed to get connector config: " + err.Error())
	}
	lambda.Start(handler(config))
}
