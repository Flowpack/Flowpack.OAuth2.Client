<?php
namespace Flowpack\OAuth2\Client\ViewHelpers\Uri;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Flowpack\OAuth2\Client\UriBuilder;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Fluid\Core\ViewHelper\AbstractViewHelper;

/**
 */
class AuthorizationViewHelper extends AbstractViewHelper {

	/**
	 * @Flow\Inject
	 * @var UriBuilder
	 */
	protected $oauthUriBuilder;

	/**
	 * @param string $providerName The name of the authentication provider as defined in the Settings
	 * @return string
	 */
	public function render($providerName) {
		return $this->oauthUriBuilder->getAuthorizationUri($providerName);
	}

}
