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
use OCA\UserOIDC\Service\JwtService;
use OCA\UserOIDC\Service\SignatureException;
use OCA\UserOIDC\Service\InvalidTokenException;
use OCA\UserOIDC\Service\AttributeValueException;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;

use OCP\ILogger;
use OCP\IRequest;
use OCP\IURLGenerator;

use OCP\User\Backend\ABackend;
use OCP\User\Backend\ICustomLogout;
use OCP\User\Backend\IGetDisplayNameBackend;
use OCP\User\Backend\IPasswordConfirmationBackend;


use OCP\AppFramework\Db\DoesNotExistException;
use OCP\Authentication\IApacheBackend;
use OCP\DB\Exception;

use Base64Url\Base64Url;

class Backend extends ABackend implements IPasswordConfirmationBackend, IGetDisplayNameBackend, IApacheBackend, ICustomLogout {
	/** @var ILogger */
	private $logger;
	/** @var IRequest */
	private $request;
	/** @var IURLGenerator */
	private $urlGenerator;
	/** @var UserMapper */
	private $userMapper;
	/** @var ProviderMapper */
	private $providerMapper;
	/** @var ProviderService */
	private $providerService;
	/** @var UserService */
	private $userService;
	/** @var DiscoveryService */
	private $discoveryService;
	/** @var JwtService */
	private $jwtService;

	public function __construct(ILogger $logger,
								IRequest $request,
                                IURLGenerator $urlGenerator,
								ProviderMapper $providerMapper,
								ProviderService $providerService,
								UserMapper $userMapper,
								UserService $userService,
								DiscoveryService $discoveryService,
								JwtService $jwtService) {
		$this->userMapper = $userMapper;
		$this->logger = $logger;
		$this->request = $request;
        $this->urlGenerator = $urlGenerator;
		$this->providerMapper = $providerMapper;
		$this->providerService = $providerService;
		$this->userService = $userService;
		$this->discoveryService = $discoveryService;
		$this->jwtService = $jwtService;
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
            $this->logger->logException($e, [
                'message' => 'Failed to delete OIDC user:' . $e->getMessage(),
                'level' => ILogger::ERROR,
                'app' => 'user_oidc'
            ]);
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
			return "user.unknown";
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
		// Authorization is also send for other tokens, so make sure the handling here only goes for bearer
		return (preg_match('/^\s*bearer\s+/i', $headerToken) != false);
	}

	/**
	 * {@inheritdoc}
	 */
	public function getLogoutUrl() : string {
        return $this->urlGenerator->linkToRoute(Application::APP_ID . '.logout.sessionlogout');
    }

	/**
	 * This function sets an https status code here (early in the failing backend operation)
	 * to pass on bearer errors cleanly with correct status code and a readable reason
	 *
	 * For this,  there is a "tricky" setting of a header needed to make it working in all
	 * known situations, see
	 * https://stackoverflow.com/questions/3258634/php-how-to-send-http-response-code
	 */
	protected function sendHttpStatus(int $httpStatusCode, string $httpStatusMsg) {
		$phpSapiName = substr(php_sapi_name(), 0, 3);
		if ($phpSapiName == 'cgi' || $phpSapiName == 'fpm') {
			header('Status: ' . $httpStatusCode . ' ' . $httpStatusMsg);
		} else {
			$protocol = isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0';
			header($protocol . ' ' . $httpStatusCode . ' ' . $httpStatusMsg);
		}
	}

	/**
	 * Return the id of the current user
	 * @return string
	 * @since 6.0.0
	 */
	public function getCurrentUserId() {
		// get the bearer token from headers
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);
		$rawToken = preg_replace('/^\s*bearer\s+/i', '', $headerToken);
		if ($rawToken === '') {
			$this->logger->warning('Authorization header without bearer token received');
			//$this->setStatus(403, "empty bearer token");
			return '';
		}

		foreach ($this->providerMapper->getProviders() as $provider) {
			try {
                $sharedSecret = $provider->getBearerSecret();
                $bearerToken = $this->jwtService->decryptToken($rawToken, $provider->getBearerSecret());
				$this->jwtService->verifySignature($bearerToken, $provider->getBearerSecret());
				$claims = $this->jwtService->decodeClaims($bearerToken);
				$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
				$this->logger->debug('Valid bearer token: ' . json_encode($claims));
	
				$providerId = $provider->getId();
				try {
					$uid = $this->userService->determineUID($providerId, $claims);
					$displayname = $this->userService->determineDisplayname($providerId, $claims);
					$email = $this->userService->determineEmail($providerId, $claims);
					$quota = $this->userService->determineQuota($providerId, $claims);
				} catch (AttributeValueException $eAttribute) {
					$this->logger->error('Invalid token (access) claims value:' . $eAttribute->getMessage());
					return '';
				}

				$userReaction = $this->userService->changeUserAccount($uid, $displayname, $email, $quota, $claims);
				if ($userReaction->isAccessAllowed()) {
					$this->logger->info("{$uid}: Bearer authorized");
					return $uid;
				} else {
					$this->logger->info("{$uid}: Bearer rejected, " + $userReaction->getReason());
					return '';
				}
			} catch (SignatureException $eSignature) {
				// only the key seems not to fit, so try the next provider
				$this->logger->debug("Invalid sign: " . $eSignature->getMessage());
				continue;
			} 
			catch (InvalidTokenException $eToken) {
				// there is
				$this->logger->error('Invalid token: ' . $eToken->getMessage());
				return '';
			}
			catch (\Throwable $e) {
				// there is
				$this->logger->debug('Non matching provider, continue: ' . $e->getMessage());
				continue;
				//return '';
			}
		}

		$this->logger->error('Invalid token (access): Not matching key found');
		return '';
	}
}
