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
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\User\Validator\SelfEncodedValidator;
use OCA\UserOIDC\User\Validator\UserInfoValidator;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCA\UserOIDC\Vendor\Firebase\JWT\SignatureInvalidException;
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
	/** @var UserService */
	private $userService;
	/** @var DiscoveryService */
	private $discoveryService;

	public function __construct(UserMapper $userMapper,
								LoggerInterface $logger,
								IRequest $request,
								ProviderMapper $providerMapper,
								ProviderService $providerService,
								UserService $userService,
								DiscoveryService $discoveryService) {
		$this->userMapper = $userMapper;
		$this->logger = $logger;
		$this->request = $request;
		$this->providerMapper = $providerMapper;
		$this->providerService = $providerService;
		$this->userService = $userService;
		$this->discoveryService = $discoveryService;
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
		// Authorisation is also send for other tokens, so make sure the handling here only goes for bearer
		//return $headerToken !== '';
		return preg_match('/^\s*bearer\s+/i', $headerToken);
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
		$bearerToken = preg_replace('/^\s*bearer\s+/i', '', $headerToken);
		if ($bearerToken === '') {
			$this->logger->warning('Autorisation header without bearer token received');
			return '';
		}

		JWT::$leeway = 60;
		foreach ($this->providerMapper->getProviders() as $provider) {
			// try to decode the bearer token
			try {
				$this->logger->debug('Bearer access token(segments=' . count(explode('.', $bearerToken)) . ')=' . $bearerToken);
				$payload = JWT::decode($bearerToken, $this->discoveryService->obtainJWK($provider), array_keys(JWT::$supported_algs));	
				$this->logger->debug('Bearer access payload=');
		        // JWT decode has already done the following steps
		        // @throws DomainException              Algorithm was not provided
		        // @throws UnexpectedValueException     Provided JWT was invalid
		        // @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
		        // @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
		        // @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
		        // @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
		        //
		        // For details:
		        // @see https://github.com/firebase/php-jwt

				$clientId = $provider->getClientId();
				if ($payload->aud !== $clientId && !in_array($clientId, $payload->aud, true)) {
					$this->logger->error("Invalid token (access): Token signature ok, but audience does not fit!");
					return '';
				}
	
				try {
					$this->logger->error('Decoded bearer token:' . json_encode($payload));
					$user = $this->userService->userFromToken($provider->getIdentifier(), $payload);
					$this->logger->error('User ' . $user->getUID() . ' authorized by Bearer');
					return $user->getUID();
				} catch (AttributeValueException $eAttribute) {
					$this->logger->error('Invalid token (access) claims:' . $eAttribute->getMessage());
					return '';
				}
			}
			// catch (SignatureInvalidException $eSignature) {
				// only the key seems not to fit, so try the next provider
			//	$this->logger->debug('Invalid provider key:' . $e->getMessage());
			//	continue;
			//} 
			catch (Throwable $e) {
				// there is
				$this->logger->error('Invalid token (general):' . $e->getMessage());
				return '';
			}
		}

		$this->logger->error('Invalid token (access): Not matching key found');
		return '';
	}
}
