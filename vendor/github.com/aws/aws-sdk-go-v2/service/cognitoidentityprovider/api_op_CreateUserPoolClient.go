// Code generated by smithy-go-codegen DO NOT EDIT.

package cognitoidentityprovider

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates the user pool client. When you create a new user pool client, token
// revocation is automatically activated. For more information about revoking
// tokens, see RevokeToken
// (https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html).
func (c *Client) CreateUserPoolClient(ctx context.Context, params *CreateUserPoolClientInput, optFns ...func(*Options)) (*CreateUserPoolClientOutput, error) {
	if params == nil {
		params = &CreateUserPoolClientInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateUserPoolClient", params, optFns, c.addOperationCreateUserPoolClientMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateUserPoolClientOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents the request to create a user pool client.
type CreateUserPoolClientInput struct {

	// The client name for the user pool client you would like to create.
	//
	// This member is required.
	ClientName *string

	// The user pool ID for the user pool where you want to create a user pool client.
	//
	// This member is required.
	UserPoolId *string

	// The access token time limit. After this limit expires, your user can't use their
	// access token. To specify the time unit for AccessTokenValidity as seconds,
	// minutes, hours, or days, set a TokenValidityUnits value in your API request. For
	// example, when you set AccessTokenValidity to 10 and TokenValidityUnits to hours,
	// your user can authorize access with their access token for 10 hours. The default
	// time unit for AccessTokenValidity in an API request is hours. Valid range is
	// displayed below in seconds.
	AccessTokenValidity *int32

	// The allowed OAuth flows. code Use a code grant flow, which provides an
	// authorization code as the response. This code can be exchanged for access tokens
	// with the /oauth2/token endpoint. implicit Issue the access token (and,
	// optionally, ID token, based on scopes) directly to your user. client_credentials
	// Issue the access token from the /oauth2/token endpoint directly to a non-person
	// user using a combination of the client ID and client secret.
	AllowedOAuthFlows []types.OAuthFlowType

	// Set to true if the client is allowed to follow the OAuth protocol when
	// interacting with Amazon Cognito user pools.
	AllowedOAuthFlowsUserPoolClient bool

	// The allowed OAuth scopes. Possible values provided by OAuth are phone, email,
	// openid, and profile. Possible values provided by Amazon Web Services are
	// aws.cognito.signin.user.admin. Custom scopes created in Resource Servers are
	// also supported.
	AllowedOAuthScopes []string

	// The user pool analytics configuration for collecting metrics and sending them to
	// your Amazon Pinpoint campaign. In Amazon Web Services Regions where Amazon
	// Pinpoint isn't available, user pools only support sending events to Amazon
	// Pinpoint projects in Amazon Web Services Region us-east-1. In Regions where
	// Amazon Pinpoint is available, user pools support sending events to Amazon
	// Pinpoint projects within that same Region.
	AnalyticsConfiguration *types.AnalyticsConfigurationType

	// Amazon Cognito creates a session token for each API request in an authentication
	// flow. AuthSessionValidity is the duration, in minutes, of that session token.
	// Your user pool native user must respond to each authentication challenge before
	// the session expires.
	AuthSessionValidity *int32

	// A list of allowed redirect (callback) URLs for the IdPs. A redirect URI must:
	//
	// *
	// Be an absolute URI.
	//
	// * Be registered with the authorization server.
	//
	// * Not
	// include a fragment component.
	//
	// See OAuth 2.0 - Redirection Endpoint
	// (https://tools.ietf.org/html/rfc6749#section-3.1.2). Amazon Cognito requires
	// HTTPS over HTTP except for http://localhost for testing purposes only. App
	// callback URLs such as myapp://example are also supported.
	CallbackURLs []string

	// The default redirect URI. Must be in the CallbackURLs list. A redirect URI
	// must:
	//
	// * Be an absolute URI.
	//
	// * Be registered with the authorization server.
	//
	// *
	// Not include a fragment component.
	//
	// See OAuth 2.0 - Redirection Endpoint
	// (https://tools.ietf.org/html/rfc6749#section-3.1.2). Amazon Cognito requires
	// HTTPS over HTTP except for http://localhost for testing purposes only. App
	// callback URLs such as myapp://example are also supported.
	DefaultRedirectURI *string

	// Activates the propagation of additional user context data. For more information
	// about propagation of user context data, see  Adding advanced security to a user
	// pool
	// (https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-advanced-security.html).
	// If you don’t include this parameter, you can't send device fingerprint
	// information, including source IP address, to Amazon Cognito advanced security.
	// You can only activate EnablePropagateAdditionalUserContextData in an app client
	// that has a client secret.
	EnablePropagateAdditionalUserContextData *bool

	// Activates or deactivates token revocation. For more information about revoking
	// tokens, see RevokeToken
	// (https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html).
	// If you don't include this parameter, token revocation is automatically activated
	// for the new user pool client.
	EnableTokenRevocation *bool

	// The authentication flows that are supported by the user pool clients. Flow names
	// without the ALLOW_ prefix are no longer supported, in favor of new names with
	// the ALLOW_ prefix. Values with ALLOW_ prefix must be used only along with the
	// ALLOW_ prefix. Valid values include: ALLOW_ADMIN_USER_PASSWORD_AUTH Enable admin
	// based user password authentication flow ADMIN_USER_PASSWORD_AUTH. This setting
	// replaces the ADMIN_NO_SRP_AUTH setting. With this authentication flow, Amazon
	// Cognito receives the password in the request instead of using the Secure Remote
	// Password (SRP) protocol to verify passwords. ALLOW_CUSTOM_AUTH Enable Lambda
	// trigger based authentication. ALLOW_USER_PASSWORD_AUTH Enable user
	// password-based authentication. In this flow, Amazon Cognito receives the
	// password in the request instead of using the SRP protocol to verify passwords.
	// ALLOW_USER_SRP_AUTH Enable SRP-based authentication. ALLOW_REFRESH_TOKEN_AUTH
	// Enable the authflow that refreshes tokens. If you don't specify a value for
	// ExplicitAuthFlows, your user client supports ALLOW_USER_SRP_AUTH and
	// ALLOW_CUSTOM_AUTH.
	ExplicitAuthFlows []types.ExplicitAuthFlowsType

	// Boolean to specify whether you want to generate a secret for the user pool
	// client being created.
	GenerateSecret bool

	// The ID token time limit. After this limit expires, your user can't use their ID
	// token. To specify the time unit for IdTokenValidity as seconds, minutes, hours,
	// or days, set a TokenValidityUnits value in your API request. For example, when
	// you set IdTokenValidity as 10 and TokenValidityUnits as hours, your user can
	// authenticate their session with their ID token for 10 hours. The default time
	// unit for AccessTokenValidity in an API request is hours. Valid range is
	// displayed below in seconds.
	IdTokenValidity *int32

	// A list of allowed logout URLs for the IdPs.
	LogoutURLs []string

	// Errors and responses that you want Amazon Cognito APIs to return during
	// authentication, account confirmation, and password recovery when the user
	// doesn't exist in the user pool. When set to ENABLED and the user doesn't exist,
	// authentication returns an error indicating either the username or password was
	// incorrect. Account confirmation and password recovery return a response
	// indicating a code was sent to a simulated destination. When set to LEGACY, those
	// APIs return a UserNotFoundException exception if the user doesn't exist in the
	// user pool. Valid values include:
	//
	// * ENABLED - This prevents user
	// existence-related errors.
	//
	// * LEGACY - This represents the early behavior of
	// Amazon Cognito where user existence related errors aren't prevented.
	PreventUserExistenceErrors types.PreventUserExistenceErrorTypes

	// The read attributes.
	ReadAttributes []string

	// The refresh token time limit. After this limit expires, your user can't use
	// their refresh token. To specify the time unit for RefreshTokenValidity as
	// seconds, minutes, hours, or days, set a TokenValidityUnits value in your API
	// request. For example, when you set RefreshTokenValidity as 10 and
	// TokenValidityUnits as days, your user can refresh their session and retrieve new
	// access and ID tokens for 10 days. The default time unit for RefreshTokenValidity
	// in an API request is days. You can't set RefreshTokenValidity to 0. If you do,
	// Amazon Cognito overrides the value with the default value of 30 days. Valid
	// range is displayed below in seconds.
	RefreshTokenValidity int32

	// A list of provider names for the identity providers (IdPs) that are supported on
	// this client. The following are supported: COGNITO, Facebook, Google,
	// SignInWithApple, and LoginWithAmazon. You can also specify the names that you
	// configured for the SAML and OIDC IdPs in your user pool, for example MySAMLIdP
	// or MyOIDCIdP.
	SupportedIdentityProviders []string

	// The units in which the validity times are represented. The default unit for
	// RefreshToken is days, and default for ID and access tokens are hours.
	TokenValidityUnits *types.TokenValidityUnitsType

	// The user pool attributes that the app client can write to. If your app client
	// allows users to sign in through an IdP, this array must include all attributes
	// that you have mapped to IdP attributes. Amazon Cognito updates mapped attributes
	// when users sign in to your application through an IdP. If your app client does
	// not have write access to a mapped attribute, Amazon Cognito throws an error when
	// it tries to update the attribute. For more information, see Specifying IdP
	// Attribute Mappings for Your user pool
	// (https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html).
	WriteAttributes []string

	noSmithyDocumentSerde
}

// Represents the response from the server to create a user pool client.
type CreateUserPoolClientOutput struct {

	// The user pool client that was just created.
	UserPoolClient *types.UserPoolClientType

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateUserPoolClientMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpCreateUserPoolClient{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpCreateUserPoolClient{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpCreateUserPoolClientValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateUserPoolClient(options.Region), middleware.Before); err != nil {
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
	return nil
}

func newServiceMetadataMiddleware_opCreateUserPoolClient(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "cognito-idp",
		OperationName: "CreateUserPoolClient",
	}
}