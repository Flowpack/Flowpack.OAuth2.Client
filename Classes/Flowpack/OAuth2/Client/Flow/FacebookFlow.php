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
use TYPO3\Flow\Configuration\ConfigurationManager;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Policy\PolicyService;
use TYPO3\Flow\Validation\ValidatorResolver;
use TYPO3\Party\Domain\Model\ElectronicAddress;
use TYPO3\Party\Domain\Model\Person;
use TYPO3\Party\Domain\Model\PersonName;
use TYPO3\Party\Domain\Repository\PartyRepository;

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
     * @var \TYPO3\Flow\Persistence\PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * @Flow\Inject
     * @var \TYPO3\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Utility\FacebookApiClient
     */
    protected $facebookApiClient;

    /**
     * @Flow\Inject
     * @var PartyRepository
     */
    protected $partyRepository;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var ValidatorResolver
     */
    protected $validatorResolver;

    /**
     * Will contain the user data given by the remote authentication service.
     * So far, this would be, for example,
     *  'id' (2) => '100006517130975' (15)
     *  'name' (4) => 'Rainer Wein' (11)
     *  'first_name' (10) => 'Rainer' (6)
     *  'last_name' (9) => 'Wein' (4)
     *  'link' (4) => 'https://www.facebook.com/profile.php?id=100006517130975' (55)
     *  'birthday' (8) => '08/28/1980' (10)
     *  'gender' (6) => 'female' (6)
     *  'email' (5) => 'rainer_izygemu_wein@tfbnw.net' (29)
     *  'timezone' (8) => integer 1
     *  'locale' (6) => 'de_DE' (5)
     *  'updated_time' (12) => '2013-11-12T09:12:35+0000' (24)
     *
     * @var array
     */
    protected $authenticationServicesUserData = array();

    /**
     * 0 => 'email',
     * 1 => 'first_name',
     * 2 => 'last_name'
     *
     * @var array
     */
    protected $authenticationServicesFields = array();

    /**
     * @var array
     */
    protected $tokenForeignAccounts = array();

    /**
     * @param AbstractClientToken $token
     * @return TokenInterface
     */
    public function getTokenOfForeignAccountOf(AbstractClientToken $token)
    {
        $foreignAccount = $this->getForeignAccountFor($token);
        /** @var $token TokenInterface */
        foreach ($this->securityContext->getAuthenticationTokens() as $token) {
            if ($token->getAccount() === $foreignAccount) {
                return $token;
            }
        }
        return null;
    }

    /**
     * @param AbstractClientToken $token
     * @return Account
     */
    public function getForeignAccountFor(AbstractClientToken $token)
    {
        if (!array_key_exists((string)$token, $this->tokenForeignAccounts)) {
            if (!isset($this->authenticationServicesUserData[(string)$token])) {
                $this->initializeUserData($token);
            }
            $this->tokenForeignAccounts[(string)$token] = $this->accountRepository->findOneByAccountIdentifier($this->authenticationServicesUserData[(string)$token]['email']);
        }
        return $this->tokenForeignAccounts[(string)$token];
    }

    /**
     * @param TokenInterface $foreignAccountToken
     * @param AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty
     */
    public function setPartyOfAuthenticatedTokenAndAttachToAccountFor(TokenInterface $foreignAccountToken, AbstractClientToken $possibleOAuthTokenAuthenticatedWithoutParty)
    {
        $oauthAccount = $possibleOAuthTokenAuthenticatedWithoutParty->getAccount();
        // TODO: this must be properly specifiable (the Roles to add)
        #$oauthAccount->setRoles();
        $oauthAccount->setParty($foreignAccountToken->getAccount()->getParty());
        $this->accountRepository->update($oauthAccount);
    }

    /**
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
        $this->facebookApiClient->setCurrentAccessToken($credentials['accessToken']);
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
