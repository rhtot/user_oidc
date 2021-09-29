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

use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWK;
use OCP\Http\Client\IClientService;
use Psr\Log\LoggerInterface;

class DiscoveryService {

	/** @var LoggerInterface */
	private $logger;

	/** @var IClientService */
	private $clientService;

	private $cached_jwks = null;

	public function __construct(LoggerInterface $logger, IClientService $clientService) {
		$this->logger = $logger;
		$this->clientService = $clientService;
	}

	public function obtainDiscovery(Provider $provider): array {
		$url = $provider->getDiscoveryEndpoint();
		$client = $this->clientService->newClient();

		$this->logger->debug('Obtaining discovery endpoint: ' . $url);
		$response = $client->get($url);

		return json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
	}




	/**
	 *  
	 * Cache once retrieved jwks on each node to speed avoid
	 * unnneccessary roundtrips for bearer tokens.
	 * 
	 * Each compute node will retreive jwks keys once and then only use the
	 * cached ones.
	 */
	public function obtainJWK(Provider $provider): array {

		if (is_null($this->cached_jwks)) {
			$discovery = $this->obtainDiscovery($provider);
			$client = $this->clientService->newClient();
			$this->cached_jwks = json_decode($client->get($discovery['jwks_uri'])->getBody(), true);
		}

		return JWK::parseKeySet($this->cached_jwks);
	}

	public function obtainKeyByAlg(Provider $provider, string $alg): array {

		if (is_null($this->cached_jwks)) {
			$discovery = $this->obtainDiscovery($provider);
			$client = $this->clientService->newClient();
			$this->cached_jwks = json_decode($client->get($discovery['jwks_uri'])->getBody(), true);
		}

		return JWK::parseKeySet($this->cached_jwks);
	}


}
