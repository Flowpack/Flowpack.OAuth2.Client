<?php
namespace Flowpack\OAuth2\Client\Provider;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Log\SecurityLoggerInterface;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 */
class FacebookProvider extends AbstractClientProvider
{

    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $securityLogger;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Endpoint\FacebookTokenEndpoint
     */
    protected $facebookTokenEndpoint;

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof AbstractClientToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1383754993);
        }

        $credentials = $authenticationToken->getCredentials();

        // Inspect the received access token as documented in https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/
        $tokenInformation = $this->facebookTokenEndpoint->requestValidatedTokenInformation($credentials['accessToken']);
        if ($tokenInformation === false) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // Check if the permitted scopes suffice:
        $necessaryScopes = $this->options['scopes'];
        $scopesHavingPermissionFor = $tokenInformation['scopes'];
        $requiredButNotPermittedScopes = array_diff($necessaryScopes, $scopesHavingPermissionFor);
        if (count($requiredButNotPermittedScopes) > 0) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            $this->securityLogger->log('The permitted scopes do not satisfy the required once.', LOG_NOTICE, array('necessaryScopes' => $necessaryScopes, 'allowedScopes' => $scopesHavingPermissionFor));
            return;
        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        /** @var $account \TYPO3\Flow\Security\Account */
        $account = null;
        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($tokenInformation, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findByAccountIdentifierAndAuthenticationProviderName($tokenInformation['user_id'], $providerName);
        });
        if ($account === null) {
            $account = new Account();
            $account->setAccountIdentifier($tokenInformation['user_id']);
            $account->setAuthenticationProviderName($providerName);
            $this->accountRepository->add($account);
        }
        $authenticationToken->setAccount($account);

        // request long-live token and attach that to the account
        $longLivedToken = $this->facebookTokenEndpoint->requestLongLivedToken($credentials['accessToken']);
        $account->setCredentialsSource($longLivedToken);
        $this->accountRepository->update($account);
    }

    /**
     * Returns the class names of the tokens this provider is responsible for.
     *
     * @return array The class name of the token this provider is responsible for
     */
    public function getTokenClassNames()
    {
        return array('Flowpack\OAuth2\Client\Token\FacebookToken');
    }
}
