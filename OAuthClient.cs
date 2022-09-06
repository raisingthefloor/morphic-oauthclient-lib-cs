// Copyright 2021 Raising the Floor - US, Inc.
//
// Licensed under the New BSD license. You may not use this file except in
// compliance with this License.
//
// You may obtain a copy of the License at
// https://github.com/raisingthefloor/morphic-oauthclient-lib-cs/blob/main/LICENSE
//
// The R&D leading to these results received funding from the:
// * Rehabilitation Services Administration, US Dept. of Education under
//   grant H421A150006 (APCP)
// * National Institute on Disability, Independent Living, and
//   Rehabilitation Research (NIDILRR)
// * Administration for Independent Living & Dept. of Education under grants
//   H133E080022 (RERC-IT) and H133E130028/90RE5003-01-00 (UIITA-RERC)
// * European Union's Seventh Framework Programme (FP7/2007-2013) grant
//   agreement nos. 289016 (Cloud4all) and 610510 (Prosperity4All)
// * William and Flora Hewlett Foundation
// * Ontario Ministry of Research and Innovation
// * Canadian Foundation for Innovation
// * Adobe Foundation
// * Consumer Electronics Association Foundation

using Morphic.Core;
using Morphic.OAuth.Rfc6749;
using Morphic.OAuth.Rfc7591;
using Morphic.OAuth.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

namespace Morphic.OAuth;

public class OAuthClient
{
    public string? ClientId { get; private set; } = null;
    public string? ClientSecret { get; private set; } = null;

    private OAuthTokenEndpointAuthMethod _tokenEndpointAuthMethod;
    public OAuthTokenEndpointAuthMethod TokenEndpointAuthMethod { 
        get
        {
            return _tokenEndpointAuthMethod;
        }
        set 
        {
            if (this.ClientSecret is null)
            {
                switch (value)
                {
                    case OAuthTokenEndpointAuthMethod.None:
                        // this is fine
                        break;
                    case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
                    case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                        throw new ArgumentOutOfRangeException("OAuth clients without client secrets cannot use this token endpoint auth method");
                    default:
                        throw new Exception("invalid code path");
                }
            } 
            else /* if (this.ClientSecret is not null) */
            {
                switch (value)
                {
                    case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
                    case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                        // these are fine
                        break;
                    case OAuthTokenEndpointAuthMethod.None:
                        throw new ArgumentOutOfRangeException("OAuth clients with client secrets cannot use this token endpoint auth method");
                    default:
                        throw new Exception("invalid code path");
                }
            }

            _tokenEndpointAuthMethod = value;
        }
    }

    public OAuthClient()
    {
        this.TokenEndpointAuthMethod = OAuthTokenEndpointAuthMethod.None;
    }

    public OAuthClient(string clientId)
    {
        this.ClientId = clientId;
        //
        // default token endpoint auth method for a client with an clientId is ClientSecretBasic
        this.TokenEndpointAuthMethod = OAuthTokenEndpointAuthMethod.ClientSecretBasic;
    }

    public OAuthClient(string clientId, string clientSecret)
    {
        this.ClientId = clientId;
        this.ClientSecret = clientSecret;
        //
        // default token endpoint auth method for a client with an clientId is ClientSecretBasic
        this.TokenEndpointAuthMethod = OAuthTokenEndpointAuthMethod.ClientSecretBasic;
    }


    #region "Client Registration API"


    #endregion "Client Registration API"


    #region "Token Auth API"

    public struct RequestAccessTokenResponse
    {
        public string AccessToken;
        public string TokenType;
        public double? ExpiresIn;
        public string? RefreshToken;
        public string? Scope;
    }
    public record RequestAccessTokenError : MorphicAssociatedValueEnum<RequestAccessTokenError.Values>
    {
        // enum members
        public enum Values
        {
            HttpError,
            // TODO: do we want to call this "InvalidSuccessResponse"?  For client registration, we called it "InvalidClientInformationResponse"; what is the correct name here?  [Success Response might be the official term?]
            InvalidSuccessResponse,
            NetworkError,
            OAuthError,
            Timeout,
            UnsupportedOAuthError
        }

        // functions to create member instances
        public static RequestAccessTokenError HttpError(HttpStatusCode httpStatusCode) => new RequestAccessTokenError(Values.HttpError) { HttpStatusCode = httpStatusCode };
        public static RequestAccessTokenError InvalidSuccessResponse(string? responseContent) => new RequestAccessTokenError(Values.InvalidSuccessResponse) { ResponseContent = responseContent };
        public static RequestAccessTokenError NetworkError => new RequestAccessTokenError(Values.NetworkError);
        public static RequestAccessTokenError OAuthError(Rfc6749AccessTokenErrorResponseErrorCodes error, string? errorDescription, string? errorUri) => new RequestAccessTokenError(Values.OAuthError) { Error = error, ErrorDescription = errorDescription, ErrorUri = errorUri };
        public static RequestAccessTokenError Timeout => new RequestAccessTokenError(Values.Timeout);
        public static RequestAccessTokenError UnsupportedOAuthError(string unsupportedError, string? errorDescription, string? errorUri) => new RequestAccessTokenError(Values.UnsupportedOAuthError) { UnsupportedError = unsupportedError, ErrorDescription = errorDescription, ErrorUri = errorUri };

        // associated values
        public Rfc6749AccessTokenErrorResponseErrorCodes? Error { get; private set; }
        public string? ErrorDescription { get; private set; }
        public string? ErrorUri { get; private set; }
        public HttpStatusCode? HttpStatusCode { get; private set; }
        public string? ResponseContent { get; private set; }
        public string? UnsupportedError { get; private set; }

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private RequestAccessTokenError(Values value) : base(value) { }
    }
    public async Task<MorphicResult<RequestAccessTokenResponse, RequestAccessTokenError>> RequestAccessTokenUsingClientCredentialsGrantAsync(Uri tokenEndpointUri, string? scope)
    {
        // per RFC 6749 Section 2.3.1, all token requests using a password (i.e. a client secret) must be secured via TLS
        if (tokenEndpointUri.Scheme.ToLowerInvariant() != "https")
        {
            throw new ArgumentException("Argument \"tokenEndpointUri\" must be secured via https; ClientSecrets may not be transmitted in cleartext", nameof(tokenEndpointUri));
        }

        // assemble our message's content
        var postParameters = new List<KeyValuePair<string?, string?>>();
        postParameters.Add(new KeyValuePair<string?, string?>("grant_type", "client_credentials"));
        if (scope is not null)
        {
            postParameters.Add(new KeyValuePair<string?, string?>("scope", scope));
        }

        string? encodedClientIdAndSecret = null;

        switch (this.TokenEndpointAuthMethod)
        {
            case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                // if our token endpoint auth method is ClientSecretPost, then encode the client id and client secret (which must be present) as post parameters
                postParameters.Add(new KeyValuePair<string?, string?>("client_id", this.ClientId!));
                postParameters.Add(new KeyValuePair<string?, string?>("client_secret", this.ClientSecret!));
                break;
            case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
                // if our token endpoint auth method is ClientSecretBasic, then encode the client id and client secret for the Authorization header
                encodedClientIdAndSecret = Utils.EncodingUtils.EncodeUsernameAndPasswordForOAuthBasicAuthorization(this.ClientId!, this.ClientSecret!);
                break;
            case OAuthTokenEndpointAuthMethod.None:
                throw new InvalidOperationException("To use this grant type to request an access token, a client's TokenEndpointAuthMethod must support transmitting the client secret");
            default:
                throw new Exception("invalid code path");
        }

        // assemble our request message
        //
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpointUri);
        //
        // set the content (along with the content-type header)
        requestMessage.Content = new FormUrlEncodedContent(postParameters);
        //
        // set the authorization header (if we're using the ClientSecretBasic token endpoint auth method)
        if (encodedClientIdAndSecret is not null)
        {
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", encodedClientIdAndSecret);
        }
        //
        // NOTE: although the OAuth spec doesn't specify it as a requirement, we set our accept header to "application/json"; if this causes troubles in production we can remove it
        // set the Accept header
        requestMessage.Headers.Accept.Clear();
        requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(EncodingUtils.CONTENT_TYPE_APPLICATION_JSON));

        // send our request (and capture the response)
        using (var httpClient = new HttpClient())
        {
            HttpResponseMessage responseMessage;
            try
            {
                responseMessage = await httpClient.SendAsync(requestMessage);
            }
            catch (HttpRequestException)
            {
                // network/http error (connectivity, dns, tls)
                return MorphicResult.ErrorResult(RequestAccessTokenError.NetworkError);
            }
            catch (TaskCanceledException ex)
            {
                if (ex.InnerException?.GetType() == typeof(TimeoutException))
                {
                    // timeout
                    return MorphicResult.ErrorResult(RequestAccessTokenError.Timeout);
                }
                else
                {
                    // we should not have any other TaskCanceledExceptions
                    throw;
                }
            }

            switch (responseMessage.StatusCode)
            {
                case HttpStatusCode.OK:
                    {
                        // (successful) response
                        var responseContent = await responseMessage.Content.ReadAsStringAsync();

                        if (responseContent is not null)
                        {
                            // verify that the response has a content-type of application/json
                            // NOTE: we do not parse the optional character set; we assume the default character set
                            var responseContentType = responseMessage.Content.Headers.ContentType?.MediaType;
                            if (responseContentType is not null)
                            {
                                var contentTypeIsApplicationJson = EncodingUtils.VerifyContentTypeIsApplicationJson(responseContentType);
                                if (contentTypeIsApplicationJson == false)
                                {
                                    // invalid oauth successful response; return the response content
                                    return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(responseContent));
                                }
                            }
                            else
                            {
                                // invalid oauth successful response; return the response content
                                return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(responseContent));
                            }

                            // deserialize the response content
                            Rfc6749AccessTokenSuccessfulResponseContent successfulResponse;
                            try
                            {
                                successfulResponse = JsonSerializer.Deserialize<Rfc6749AccessTokenSuccessfulResponseContent>(responseContent);
                            }
                            catch
                            {
                                // invalid oauth successful response; return the response content
                                return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(responseContent));
                            }

                            var result = new RequestAccessTokenResponse();
                            // AccessToken
                            if (successfulResponse.access_token is not null)
                            {
                                result.AccessToken = successfulResponse.access_token!;
                            }
                            else
                            {
                                // invalid oauth successful response; return the response content
                                return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(responseContent));
                            }
                            // TokenType
                            if (successfulResponse.token_type is not null)
                            {
                                result.TokenType = successfulResponse.token_type!;
                            }
                            else
                            {
                                // invalid oauth successful response; return the response content
                                return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(responseContent));
                            }
                            // ExpiresIn
                            result.ExpiresIn = successfulResponse.expires_in;
                            // RefreshToken
                            result.RefreshToken = successfulResponse.refresh_token;
                            // Scope
                            result.Scope = successfulResponse.scope;

                            return MorphicResult.OkResult(result);
                        }
                        else
                        {
                            // invalid oauth successful response; return the response content
                            return MorphicResult.ErrorResult(RequestAccessTokenError.InvalidSuccessResponse(null /* responseContent */));
                        }
                    }
                case HttpStatusCode.BadRequest:
                    {
                        var responseContent = await responseMessage.Content.ReadAsStringAsync();

                        // verify that the response has a content-type of application/json
                        // NOTE: we do not parse the optional character set; we assume the default character set
                        var responseContentType = responseMessage.Content.Headers.ContentType?.MediaType;
                        if (responseContentType is not null)
                        {
                            var contentTypeIsApplicationJson = EncodingUtils.VerifyContentTypeIsApplicationJson(responseContentType);
                            if (contentTypeIsApplicationJson == false)
                            {
                                // invalid oauth error response; return the http error code
                                return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
                            }
                        }
                        else
                        {
                            // invalid oauth error response; return the http error code
                            return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
                        }

                        // deserialize the response content
                        if (responseContent is not null)
                        {
                            Rfc6749AccessTokenErrorResponseContent errorResponse;
                            try
                            {
                                errorResponse = JsonSerializer.Deserialize<Rfc6749AccessTokenErrorResponseContent>(responseContent);
                            }
                            catch
                            {
                                // invalid oauth error response; just return the http status code (as it's not an OAuth error)
                                return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
                            }

                            Rfc6749AccessTokenErrorResponseErrorCodes? error = null;
                            if (errorResponse.error is not null)
                            {
                                error = MorphicEnum<Rfc6749AccessTokenErrorResponseErrorCodes>.FromStringValue(errorResponse.error);
                                if (error is null)
                                {
                                    // missing or unknown oauth error code
                                    return MorphicResult.ErrorResult(RequestAccessTokenError.UnsupportedOAuthError(errorResponse.error, errorResponse.error_description, errorResponse.error_uri));
                                }
                            }
                            else
                            {
                                // if we did not get a valid response, return the HTTP error (as it's not an OAuth error)
                                return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
                            }

                            return MorphicResult.ErrorResult(RequestAccessTokenError.OAuthError(error.Value, errorResponse.error_description, errorResponse.error_uri));
                        }
                        else
                        {
                            // if we did not get a valid response, return the HTTP error (as it's not an OAuth error)
                            return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
                        }
                    }
                default:
                    return MorphicResult.ErrorResult(RequestAccessTokenError.HttpError(responseMessage.StatusCode));
            }
        }
    }

    #endregion "Token Auth API"

}
