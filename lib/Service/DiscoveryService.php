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

use OCP\ILogger;
use OCP\ICacheFactory;
use OCP\IMemCache;
use OCP\Http\Client\IClientService;

class DiscoveryService {
	public const CACHE_EXPIRATION = 4 * 60 * 60;
	public const CACHE_DISCOVERY = 'discovery';
	public const CACHE_JWKS = 'jwks';

	/** @var IMemCache */
	protected $cache;

	/** @var ILogger */
	private $logger;

	/** @var IClientService */
	private $clientService;

	public function __construct(ILogger $logger,
								IClientService $clientService,
								ICacheFactory $cacheFactory) {
		$this->logger = $logger;
		$this->clientService = $clientService;

		$this->cache = $cacheFactory->createDistributed("user_oidc");
	}

    /** for test purposes */
    public function invalidateCache() {
        $this->cache->remove(self::CACHE_DISCOVERY);
        $this->cache->remove(self::CACHE_JWKS);
    }

	public function obtainDiscovery(Provider $provider, int $expire = self::CACHE_EXPIRATION): array {
        $discovered = $this->cache->get(self::CACHE_DISCOVERY);
        if ( $discovered == null ) {
			$url = $provider->getDiscoveryEndpoint();
			$this->logger->debug('Obtaining discovery endpoint: ' . $url);

			$client = $this->clientService->newClient();
			$response = $client->get($url);
			$discovered = $response->getBody();
			$this->cache->set(self::CACHE_DISCOVERY, $discovered, $expire);
		}
		
		return json_decode($discovered, true, 512, JSON_THROW_ON_ERROR);
	}

	public function obtainJWK(Provider $provider, int $expire = self::CACHE_EXPIRATION): array {
        $rawJwks = $this->cache->get(self::CACHE_JWKS);
        if ( $rawJwks == null ) {
			$discovery = $this->obtainDiscovery($provider);
			$client = $this->clientService->newClient();
			$rawJwks = $client->get($discovery['jwks_uri'])->getBody();
			$this->cache->set(self::CACHE_JWKS, $rawJwks, $expire);
        }

        $jwks = json_decode($rawJwks, true);
        return JWK::parseKeySet($jwks);
	}
}
