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

use Flowpack\OAuth2\Client\Exception as OAuth2Exception;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Http\Uri;
use TYPO3\Flow\Log\SecurityLoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class GoogleTokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface
{

    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     *
     * @param string $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function requestValidatedTokenInformation($tokenToInspect, $scope = array())
    {
        $this->securityLogger->log('NEIN davor GOOGLE requestValidatedTokenInformation.', LOG_NOTICE, array('$tokenToInspect' => var_export($tokenToInspect, true)));

//        $applicationToken = $this->requestClientCredentialsGrantAccessToken($scope);
//        $this->securityLogger->log('tata GOOGLE requestClientCredentialsGrantAccessToken requestValidatedTokenInformation.', LOG_NOTICE, array('$tokenToInspect' => var_export($tokenToInspect, true), '$applicationToken' => var_export($applicationToken, true)));

        $requestArguments = array(
            'input_token' => $tokenToInspect['access_token'],
            'id_token' => $tokenToInspect['id_token']
        );

        $request = Request::create(new Uri('https://www.googleapis.com/oauth2/v3/tokeninfo?' . http_build_query($requestArguments)));
        $response = $this->requestEngine->sendRequest($request);
        $responseContent = $response->getContent();
        if ($response->getStatusCode() !== 200) {
            throw new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $responseContent), 1383758360);
        }

        $responseArray = json_decode($responseContent, true, 16, JSON_BIGINT_AS_STRING);

        $this->securityLogger->log('TATAT $responseArray.', LOG_NOTICE, array('$responseArray' => var_export($responseArray, true)));
        $responseArray['aud'] = (string)$responseArray['aud'];
        $responseArray['sub'] = (string)$responseArray['sub'];
        $clientIdentifier = (string)$this->clientIdentifier;

        if ($responseArray['aud'] !== $clientIdentifier) {
            $this->securityLogger->log('Requesting validated token information from the Google endpoint did not succeed.', LOG_NOTICE, array('response' => var_export($responseArray, true), 'clientIdentifier' => $clientIdentifier));
            return false;
        }

        return $responseArray;
    }

    /**
     * @param $shortLivedToken
     * @return string
     */
    public function requestLongLivedToken($shortLivedToken)
    {
        $this->securityLogger->log('GOOGLE requestLongLivedToken.', LOG_NOTICE, array('$shortLivedToken' => var_export($shortLivedToken, true)));
        return $this->requestAccessToken('refresh_token', array('refresh_token' => $shortLivedToken));
    }
}
