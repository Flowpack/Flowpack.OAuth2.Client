<?php
namespace Flowpack\OAuth2\Client\Endpoint;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;

/**
 */
interface TokenEndpointInterface {

	const GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';
	const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';

	/**
	 * Requests an access token for Client Credentials Grant as specified in section 4.4.2
	 *
	 * @param string $code The authorization code received from the authorization server.
	 * @param string $redirectUri REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.
	 * @param string $clientIdentifier REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.
	 * @return mixed
	 * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
	 */
	public function requestAuthorizationCodeGrantAccessToken($code, $redirectUri = NULL, $clientIdentifier = NULL);

	/**
	 * Requests an access token for Resource Owner Password Credentials Grant as specified in section 4.3.2
	 *
	 * @param string $username The resource owner username.
	 * @param string $password The resource owner password.
	 * @param array $scope The scope of the access request as described by http://tools.ietf.org/html/rfc6749#section-3.3
	 * @return mixed
	 * @see http://tools.ietf.org/html/rfc6749#section-4.3.2
	 */
	public function requestResourceOwnerPasswordCredentialsGrantAccessToken($username, $password, $scope = array());

	/**
	 * Requests an access token for Client Credentials Grant as specified in section 4.4.2
	 *
	 * @param array $scope The scope of the access request as described by http://tools.ietf.org/html/rfc6749#section-3.3
	 * @return mixed
	 * @see http://tools.ietf.org/html/rfc6749#section-4.4.2
	 */
	public function requestClientCredentialsGrantAccessToken($scope = array());

	/**
	 * @return string
	 */
	public function __toString();
}