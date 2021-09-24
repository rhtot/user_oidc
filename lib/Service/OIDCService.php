<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
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

use OCP\Http\Client\IClientService;
use OCP\AppFramework\Utility\ITimeFactory;

use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\Provider;
use Psr\Log\LoggerInterface;
use Throwable;

class OIDCService {

	/** @var LoggerInterface */
	private $logger;

	/** @var IClientService */
	private $clientService;

	/** @var ITimeFactory */
	private $timeFactory;

	/** @var ProviderMapper */
	private $providerMapper;

	public function __construct(DiscoveryService $discoveryService,
	                            LoggerInterface $logger, 
								IClientService $clientService,
								ITimeFactory $timeFactory,
								ProviderMapper $providerMapper) {
		$this->discoveryService = $discoveryService;
		$this->logger = $logger;
		$this->clientService = $clientService;
		$this->timeFactory = $timeFactory;
		$this->providerMapper = $providerMapper;
	}

	public function userinfo(Provider $provider, string $accessToken): array {
		$url = $this->discoveryService->obtainDiscovery($provider)['userinfo_endpoint'] ?? null;
		if ($url === null) {
			return [];
		}

		$client = $this->clientService->newClient();
		$this->logger->debug('Fetching user info endpoint');
		$options = [
			'headers' => [
				'Authorization' => 'Bearer ' . $accessToken,
			],
		];
		try {
			return json_decode($client->get($url, $options)->getBody(), true);
		} catch (Throwable $e) {
			return [];
		}
	}

	public function introspection(Provider $provider, string $accessToken): array {
		$url = $this->discoveryService->obtainDiscovery($provider)['introspection_endpoint'] ?? null;
		if ($url === null) {
			return [];
		}

		$client = $this->clientService->newClient();
		$this->logger->debug('Fetching user info endpoint');
		$options = [
			'headers' => [
				'Authorization' => base64_encode($provider->getClientId() . ':' . $provider->getClientSecret()),
			],
			'body' => [
				'token' => $accessToken,
			],
		];
		try {
			return json_decode($client->post($url, $options)->getBody(), true);
		} catch (Throwable $e) {
			return [];
		}
	}

	public function verifyToken(object $payload) {
		$this->logger->debug('Parsed the JWT payload: ' . json_encode($payload, JSON_THROW_ON_ERROR));

		if ($this->timeFactory->getTime() < $payload->exp) {
			$this->logger->debug('Token expired');
			throw new InvalidTokenException('token expired');
		}

		foreach($this->providerMapper->getProviders() as $provider) {
			// check all providers to verify audience
			if (($payload->aud === $clientId || in_array($provider->getClientId(), $payload->aud, true))) {
				// the first matching provider from list is applied, not all matching ones
				// I think this is ok as I cannot think of a scenario where multiple matches
				// can occur
				return $provider->getIdentifier();
			}
		}

		$this->logger->debug('This token is not for us');
		throw new InvalidTokenException('audience does not match');
	}
}
