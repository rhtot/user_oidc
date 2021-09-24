<?php
/*
 * @copyright Copyright (c) 2021 Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Service\AttributeValueException;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\ILogger;
use OCP\IUserManager;

class UserService {

    /** @var IEventDispatcher */
	private $eventDispatcher;

	/** @var ILogger */
	private $logger;

	/** @var UserMapper */
	private $userMapper;

	/** @var IUserManager */
	private $userManager;

	/** @var ProviderService */
	private $providerService;

	public function __construct(IEventDispatcher $eventDispatcher,
		                        ILogger $logger,
		                        UserMapper $userMapper,
		                        IUserManager $userManager,
                                ProviderService $providerService ) {
		$this->eventDispatcher = $eventDispatcher;
		$this->logger = $logger;
		$this->userMapper = $userMapper;
		$this->userManager = $userManager;
		$this->providerService = $providerService;
	}

	protected function determineUID(int $providerid, object $payload) {
		$uidAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_UID, 'sub');
		$mappedUserId = $payload->{$uidAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_UID, $payload, $mappedUserId);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	} 

	protected function determineDisplayname(int $providerid, object $payload) {
		$displaynameAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_DISPLAYNAME, 'name');
		$mappedDisplayName = $payload->{$displaynameAttribute} ?? null;

		if (isset($mappedDisplayName)) {
			$limitedDisplayName = mb_substr($mappedDisplayName, 0, 255);
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $payload, $limitedDisplayName);
		} else {
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $payload);
		}
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	} 

	protected function determineEmail(int $providerid, object $payload) {
		$emailAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_EMAIL, 'email');
		$mappedEmail = $payload->{$emailAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_EMAIL, $payload, $email);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	} 

	protected function determineQuota(int $providerid, object $payload) {
		$quotaAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_QUOTA, 'quota');
		$mappedQuota = $payload->{$quotaAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_QUOTA, $payload, $quota);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	} 

	/**
	 * Extract mapped values from token claims, 
	 * emit event to consider complex business rules that may override claim mapping,
	 * create OIDC user if not existing,
	 * update user fields in case of a change
	 */	
    public function userFromToken(int $providerId, object $payload) : object {
		$uid = $this->determineUID($providerId, $payload);
		if (is_null($uid)) {
			throw new AttributeValueException("cannot determine userId from token"); 
		}
		$backendUser = $this->userMapper->getOrCreate($providerId, $uid);
		$this->logger->debug($backendUser->getUserId() . ': Backend user obtained.');
		$user = $this->userManager->get($backendUser->getUserId());
		$this->logger->debug($backendUser->getUserId() . ': Associated account available');
		if (is_null($uid)) {
			throw new AttributeValueException("backend user without associated account found"); 
		}

		$displayName = $this->determineDisplayname($providerId, $payload);
		if (isset($displayName) && ($displayName != $backendUser->getDisplayName())) {
			// only modify on change
			$backendUser->setDisplayName($newDisplayName);
			$backendUser = $this->userMapper->update($backendUser);
		}

		$email = $this->determineEmail($providerId, $payload);
		if (isset($email) && ($email != $user->getEMailAddress())) {
			// only modify on change
			$user->setEMailAddress($email);
		}

		$quota = $this->determineQuota($providerId, $payload);
		if (isset($quota) && ($quota != $user->getQuota())) {
			// only modify on change
			$user->setQuota($quota);
		}
    
		return $user;
		//return array (
		//	"userBackend" => $backendUser, 
		//	"userAccount" => $user
		//);
	}
}
