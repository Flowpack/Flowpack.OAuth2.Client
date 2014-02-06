<?php
namespace Flowpack\OAuth2\Client\Utility;

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
use TYPO3\Flow\Http\Client\CurlEngine;
use TYPO3\Flow\Http\Client\RequestEngineInterface;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Http\Uri;
use TYPO3\Flow\Object\DependencyInjection\DependencyProxy;

/**
 * @Flow\Scope("singleton")
 */
class FacebookApiClient {

	/**
	 * @var RequestEngineInterface
	 */
	protected $requestEngine;

	/**
	 * @var string
	 */
	protected $endpoint = 'https://graph.facebook.com';

	/**
	 * @var string
	 */
	protected $appSecret;

	/**
	 * The access token to use for the request.
	 *
	 * @var string
	 */
	protected $currentAccessToken;

	/**
	 */
	public function initializeObject() {
		if (($this->requestEngine instanceof DependencyProxy
				&& $this->requestEngine->_getClassName() === 'TYPO3\Flow\Http\Client\CurlEngine')
			|| $this->requestEngine instanceof CurlEngine) {
			$this->requestEngine->setOption(CURLOPT_CAINFO, FLOW_PATH_PACKAGES . 'Application/Flowpack.OAuth2.Client/Resources/Private/cacert.pem');
			$this->requestEngine->setOption(CURLOPT_SSL_VERIFYPEER, TRUE);
		}
	}

	/**
	 * @param string $resource
	 * @param string $method
	 * @return \TYPO3\Flow\Http\Response
	 */
	public function query($resource, $method = 'GET') {
		$uri = new Uri($this->endpoint . $resource);
		parse_str((string)$uri->getQuery(), $query);
		$query['access_token'] = $this->currentAccessToken;
		$query['appsecret_proof'] = hash_hmac('sha256', $this->currentAccessToken, $this->appSecret);
		$uri->setQuery(http_build_query($query));

		$request = Request::create($uri, $method);
		$response = $this->requestEngine->sendRequest($request);
		return $response;
	}

	/**
	 * @param string $currentAccessToken
	 */
	public function setCurrentAccessToken($currentAccessToken) {
		$this->currentAccessToken = $currentAccessToken;
	}

};