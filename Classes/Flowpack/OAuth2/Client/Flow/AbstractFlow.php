<?php
namespace Flowpack\OAuth2\Client\Flow;

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
use TYPO3\Flow\Security\Authentication\TokenInterface;

/**
 */
abstract class AbstractFlow implements FlowInterface
{

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\Context
     */
    protected $securityContext;

    /**
     * This returns the (first) *authenticated* OAuth token which doesn't have a party attached.
     *
     *@return AbstractClientToken
     */
    public function getChargedAuthenticatedTokenHavingNoPartyAttached()
    {
        /** @var $token AbstractClientToken */
        foreach ((array)$this->securityContext->getAuthenticationTokensOfType($this->getTokenClassName()) as $token) {
            if ($token->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_SUCCESSFUL
                && ($token->getAccount() === null || $token->getAccount()->getParty() === null)
            ) {
                return $token;
            }
        }
        return null;
    }
}
