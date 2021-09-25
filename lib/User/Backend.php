<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2020, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\UserOIDC\User;

use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\OIDCService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\User\Validator\SelfEncodedValidator;
use OCA\UserOIDC\User\Validator\UserInfoValidator;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\Authentication\IApacheBackend;
use OCP\DB\Exception;
use OCP\IRequest;
use OCP\User\Backend\ABackend;
use OCP\User\Backend\IGetDisplayNameBackend;
use OCP\User\Backend\IPasswordConfirmationBackend;
use Psr\Log\LoggerInterface;

class Backend extends ABackend implements IPasswordConfirmationBackend, IGetDisplayNameBackend, IApacheBackend {
	/** @var UserMapper */
	private $userMapper;
	/** @var LoggerInterface */
	private $logger;
	/** @var IRequest */
	private $request;
	/** @var ProviderMapper */
	private $providerMapper;
	/** @var ProviderService */
	private $providerService;
	/** @var OIDCService */
	private $oidcService;
	/** @var UserService */
	private $userService;

	public function __construct(UserMapper $userMapper,
								LoggerInterface $logger,
								IRequest $request,
								ProviderMapper $providerMapper,
								ProviderService $providerService,
								//OIDCService $oidcService,
								UserService $userService) {
		$this->userMapper = $userMapper;
		$this->logger = $logger;
		$this->request = $request;
		$this->providerMapper = $providerMapper;
		$this->providerService = $providerService;
		$this->oidcService = $oidcService;
		$this->userService = $userService;
	}

	public function getBackendName(): string {
		return Application::APP_ID;
	}

	public function deleteUser($uid): bool {
		try {
			$user = $this->userMapper->getUser($uid);
			$this->userMapper->delete($user);
			return true;
		} catch (Exception $e) {
			$this->logger->error('Failed to delete user', [ 'exception' => $e ]);
			return false;
		}
	}

	public function getUsers($search = '', $limit = null, $offset = null) {
		return array_map(function ($user) {
			return $user->getUserId();
		}, $this->userMapper->find($search, $limit, $offset));
	}

	public function userExists($uid): bool {
		return $this->userMapper->userExists($uid);
	}

	public function getDisplayName($uid): string {
		try {
			$user = $this->userMapper->getUser($uid);
		} catch (DoesNotExistException $e) {
			return $uid;
		}

		return $user->getDisplayName();
	}

	public function getDisplayNames($search = '', $limit = null, $offset = null) {
		return $this->userMapper->findDisplayNames($search, $limit, $offset);
	}

	public function hasUserListings(): bool {
		return true;
	}

	public function canConfirmPassword(string $uid): bool {
		return false;
	}

	/**
	 * In case the user has been authenticated by Apache true is returned.
	 *
	 * @return boolean whether Apache reports a user as currently logged in.
	 * @since 6.0.0
	 */
	public function isSessionActive() {
		// if this returns true, getCurrentUserId is called
		// not sure if we should rather to the validation in here as otherwise it might fail for other backends or bave other side effects
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);
		return $headerToken !== '';
	}

	/**
	 * {@inheritdoc}
	 */
	public function getLogoutUrl() {
		return '';
	}

	/**
	 * Return the id of the current user
	 * @return string
	 * @since 6.0.0
	 */
	public function getCurrentUserId() {
		// TODO: this option makes only sense global or not
		// if ($this->providerService->getSetting($provider->getId(), ProviderService::SETTING_CHECK_BEARER, '0') !== '1') {
		//	$this->logger->debug('Bearer token check is disabled for provider ' . $provider->getId());
		//	return '';
		//}

		// get the bearer token from headers
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);
		$bearerToken = preg_replace('/^bearer\s+/i', '', $headerToken);
		if ($bearerToken === '') {
			$this->logger->warning('Autorisation header without bearer token received');
			return '';
		}
		
		// try to decode the bearer token
		JWT::$leeway = 60;
		try {
			// TODO: store JWK at provider to avoid unneccessary roundtrips
			$payload = JWT::decode($bearerToken, $this->discoveryService->obtainJWK($provider), array_keys(JWT::$supported_algs));
		} catch (Throwable $e) {
			$this->logger->error('Invalid token (general):' . $e->getMessage());
			return '';
		}

		$provider = null;
		try {
			$provider = $this->oidcService->verifyToken($provider, $payload); 
		} catch (InvalidTokenException $eInvalid) {
			$this->logger->error("Invalid token (type access):" . $eInvalid->getMessage());
		}

		try {
			$user = $this->userService->userFromToken($provider->getIdentifier(), $payload);
			return $user->getUID();
		} catch (AttributeValueException $eAttribute) {
			$this->logger->error('Invalid access token claims:' . $eAttribute->getMessage());
			return '';
		}
	}
}
