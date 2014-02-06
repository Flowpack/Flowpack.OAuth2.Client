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
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\TokenInterface;

/**
 */
interface FlowInterface {

	/**
	 * @return AbstractClientToken
	 */
	public function getChargedAuthenticatedTokenHavingNoPartyAttached();

	/**
	 * @param \TYPO3\Flow\Security\Authentication\TokenInterface|\Flowpack\OAuth2\Client\Token\AbstractClientToken $token
	 * @return TokenInterface
	 */
	public function getTokenOfForeignAccountOf(AbstractClientToken $token);

	/**
	 * @param AbstractClientToken $token
	 * @return Account
	 */
	public function getForeignAccountFor(AbstractClientToken $token);

	/**
	 * @param AbstractClientToken $token
	 */
	public function createPartyAndAttachToAccountFor(AbstractClientToken $token);

	/**
	 * @param TokenInterface $foreignAccountToken
	 * @param AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty
	 */
	public function setPartyOfAuthenticatedTokenAndAttachToAccountFor(TokenInterface $foreignAccountToken, AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty);

	/**
	 * Returns the token class name this flow is responsible for
	 *
	 * @return string
	 */
	public function getTokenClassName();
}