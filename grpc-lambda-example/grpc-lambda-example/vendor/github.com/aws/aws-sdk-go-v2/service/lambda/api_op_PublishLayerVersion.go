// Code generated by smithy-go-codegen DO NOT EDIT.

package lambda

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates an [Lambda layer] from a ZIP archive. Each time you call PublishLayerVersion with the
// same layer name, a new version is created.
//
// Add layers to your function with CreateFunction or UpdateFunctionConfiguration.
//
// [Lambda layer]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
func (c *Client) PublishLayerVersion(ctx context.Context, params *PublishLayerVersionInput, optFns ...func(*Options)) (*PublishLayerVersionOutput, error) {
	if params == nil {
		params = &PublishLayerVersionInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "PublishLayerVersion", params, optFns, c.addOperationPublishLayerVersionMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*PublishLayerVersionOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type PublishLayerVersionInput struct {

	// The function layer archive.
	//
	// This member is required.
	Content *types.LayerVersionContentInput

	// The name or Amazon Resource Name (ARN) of the layer.
	//
	// This member is required.
	LayerName *string

	// A list of compatible [instruction set architectures].
	//
	// [instruction set architectures]: https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html
	CompatibleArchitectures []types.Architecture

	// A list of compatible [function runtimes]. Used for filtering with ListLayers and ListLayerVersions.
	//
	// The following list includes deprecated runtimes. For more information, see [Runtime deprecation policy].
	//
	// [function runtimes]: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
	// [Runtime deprecation policy]: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtime-support-policy
	CompatibleRuntimes []types.Runtime

	// The description of the version.
	Description *string

	// The layer's software license. It can be any of the following:
	//
	//   - An [SPDX license identifier]. For example, MIT .
	//
	//   - The URL of a license hosted on the internet. For example,
	//   https://opensource.org/licenses/MIT .
	//
	//   - The full text of the license.
	//
	// [SPDX license identifier]: https://spdx.org/licenses/
	LicenseInfo *string

	noSmithyDocumentSerde
}

type PublishLayerVersionOutput struct {

	// A list of compatible [instruction set architectures].
	//
	// [instruction set architectures]: https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html
	CompatibleArchitectures []types.Architecture

	// The layer's compatible runtimes.
	//
	// The following list includes deprecated runtimes. For more information, see [Runtime use after deprecation].
	//
	// For a list of all currently supported runtimes, see [Supported runtimes].
	//
	// [Runtime use after deprecation]: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtime-deprecation-levels
	// [Supported runtimes]: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtimes-supported
	CompatibleRuntimes []types.Runtime

	// Details about the layer version.
	Content *types.LayerVersionContentOutput

	// The date that the layer version was created, in [ISO-8601 format] (YYYY-MM-DDThh:mm:ss.sTZD).
	//
	// [ISO-8601 format]: https://www.w3.org/TR/NOTE-datetime
	CreatedDate *string

	// The description of the version.
	Description *string

	// The ARN of the layer.
	LayerArn *string

	// The ARN of the layer version.
	LayerVersionArn *string

	// The layer's software license.
	LicenseInfo *string

	// The version number.
	Version int64

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationPublishLayerVersionMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsRestjson1_serializeOpPublishLayerVersion{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestjson1_deserializeOpPublishLayerVersion{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "PublishLayerVersion"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addSpanRetryLoop(stack, options); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpPublishLayerVersionValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opPublishLayerVersion(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opPublishLayerVersion(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "PublishLayerVersion",
	}
}
