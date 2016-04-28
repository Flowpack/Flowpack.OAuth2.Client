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

use Flowpack\OAuth2\Client\Exception\InvalidPartyDataException;
use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Party\Domain\Model\ElectronicAddress;
use TYPO3\Party\Domain\Model\Person;
use TYPO3\Party\Domain\Model\PersonName;
use TYPO3\Party\Domain\Repository\PartyRepository;
use TYPO3\Flow\Configuration\ConfigurationManager;

/**
 */
class FacebookFlow extends AbstractFlow implements FlowInterface
{
    /**
     * @Flow\Inject
     * @var ConfigurationManager
     */
    protected $configurationManager;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Utility\FacebookApiClient
     */
    protected $facebookApiClient;

    /**
     * Creates a party for the given account
     *
     * @param AbstractClientToken $token
     * @throws InvalidPartyDataException
     */
    public function createPartyAndAttachToAccountFor(AbstractClientToken $token)
    {
        $this->initializeUserData($token);
        $userData = $this->authenticationServicesUserData[(string)$token];

        $party = new Person();
        $party->setName(new PersonName('', $userData['first_name'], '', $userData['last_name']));
        // Todo: this is not covered by the Person implementation, we should have a solution for that
        #$party->setBirthDate(\DateTime::createFromFormat('!m/d/Y', $userData['birthday'], new \DateTimeZone('UTC')));
        #$party->setGender(substr($userData['gender'], 0, 1));
        $electronicAddress = new ElectronicAddress();
        $electronicAddress->setType(ElectronicAddress::TYPE_EMAIL);
        $electronicAddress->setIdentifier($userData['email']);
        $electronicAddress->isApproved(true);
        $party->addElectronicAddress($electronicAddress);
        $party->setPrimaryElectronicAddress($electronicAddress);

        $partyValidator = $this->validatorResolver->getBaseValidatorConjunction('TYPO3\Party\Domain\Model\Person');
        $validationResult = $partyValidator->validate($party);
        if ($validationResult->hasErrors()) {
            throw new InvalidPartyDataException('The created party does not satisfy the requirements', 1384266207);
        }

        $account = $token->getAccount();
        $account->setParty($party);
        $this->accountRepository->update($account);
        $this->partyRepository->add($party);

        $this->persistenceManager->persistAll();
    }

    /**
     * Returns the token class name this flow is responsible for
     *
     * @return string
     */
    public function getTokenClassName()
    {
        return 'Flowpack\OAuth2\Client\Token\FacebookToken';
    }

    /**
     * getting all the defined data from facebook
     * @param AbstractClientToken $token
     */
    protected function initializeUserData(AbstractClientToken $token)
    {
        $credentials = $token->getCredentials();
        $this->facebookApiClient->setCurrentAccessToken($credentials['access_token']);
        $query = $this->buildFacebookQuery();
        $content = $this->facebookApiClient->query($query)->getContent();
        $this->authenticationServicesUserData[(string)$token] = json_decode($content, true);
    }

    /**
     * builds the query from the fields in Settings.yaml
     * there is no further check if the fields are allowed in the scopes
     * for further information have a look at https://developers.facebook.com/docs/facebook-login/permissions
     *
     * @return string
     */
    protected function buildFacebookQuery()
    {
        $query = '/me';
        $this->authenticationServicesFields = $this->configurationManager->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'TYPO3.Flow.security.authentication.providers.FacebookOAuth2Provider.providerOptions.fields');
        $fields = implode(',', $this->authenticationServicesFields);

        $query = $query . '?fields=' . $fields;
        return $query;
    }
}
