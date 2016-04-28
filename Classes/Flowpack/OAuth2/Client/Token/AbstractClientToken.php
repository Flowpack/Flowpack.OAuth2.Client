<?php
namespace Flowpack\OAuth2\Client\Token;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Flowpack\OAuth2\Client\Endpoint\TokenEndpointInterface;
use Flowpack\OAuth2\Client\Exception;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Log\SecurityLoggerInterface;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\Token\AbstractToken;
use TYPO3\Flow\Security\Authentication\TokenInterface;

/**
 */
abstract class AbstractClientToken extends AbstractToken
{

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Endpoint\Resolver
     */
    protected $endpointResolver;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\UriBuilder
     */
    protected $oauthUriBuilder;

    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * @var TokenEndpointInterface
     */
    protected $tokenEndpoint;

    /**
     * @var array
     */
    protected $credentials = array('accessToken' => null);

    /**
     * The $this->authenticationProviderName property is either known when in session
     * or is set manually via the setAuthenticationProviderName. That's why we can't rely
     * on this value being present already.
     */
    protected function initializeObject()
    {
        if ($this->authenticationProviderName !== null) {
            $this->tokenEndpoint = $this->endpointResolver->getTokenEndpointForProvider($this->authenticationProviderName);
        }
    }

    /**
     * Updates the authentication credentials, the authentication manager needs to authenticate this token.
     * This could be a username/password from a login controller.
     * This method is called while initializing the security context. By returning TRUE you
     * make sure that the authentication manager will (re-)authenticate the tokens with the current credentials.
     * Note: You should not persist the credentials!
     *
     * @param ActionRequest $actionRequest The current request instance
     * @throws \InvalidArgumentException
     * @return boolean TRUE if this token needs to be (re-)authenticated
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        if ($actionRequest->getHttpRequest()->getMethod() !== 'GET'
            || $actionRequest->getInternalArgument('__oauth2Provider') !== $this->authenticationProviderName) {
            return;
        }

        if (!$actionRequest->hasArgument('code')) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            $this->securityLogger->log('There was no argument `code` provided.', LOG_NOTICE);
            return;
        }
        $code = $actionRequest->getArgument('code');
        $redirectUri = $this->oauthUriBuilder->getRedirectionEndpointUri($this->authenticationProviderName);
        try {
//            $this->credentials['accessToken'] = $this->tokenEndpoint->requestAuthorizationCodeGrantAccessToken($code, $redirectUri);
            $this->credentials = $this->tokenEndpoint->requestAuthorizationCodeGrantAccessToken($code, $redirectUri);
            $this->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
        } catch (Exception $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            $this->securityLogger->logException($exception);
            return;
        }
    }

    /**
     * @throws Exception
     * @return string
     */
    public function __toString()
    {
        if ($this->tokenEndpoint === null) {
            throw new Exception('The token endpoint implementation is not yet known to the token', 1384172817);
        }
        return (string)$this->tokenEndpoint;
    }

    /**
     * @param string $authenticationProviderName
     */
    public function setAuthenticationProviderName($authenticationProviderName)
    {
        parent::setAuthenticationProviderName($authenticationProviderName);
        $this->tokenEndpoint = $this->endpointResolver->getTokenEndpointForProvider($this->authenticationProviderName);
    }
}
