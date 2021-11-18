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

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\RedirectMiddleware;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Service\ProviderService;


use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

/**
 * This integration test gets a valid refresh token (from test env)
 * and reproduces all the steps to a bearer authentication
 * with a valid bearer token.
 * 
 * If you are authorized with the OpenID Connect provider, you can find the
 * refresh token in the response of the provider:
 * ```
 * {..."refresh_token":\"THIS_IS_THE_RIGHT_ONE", "scope":"userinfo","token_type":"Bearer" ...
 * ```
 * 
 * It also practically documents the way to get a bearer token as a
 * NextMagentaCloud partner app.
 * 
 * @group Bearer
 */
class ValidBearerFromRefreshTokenTest extends \Test\TestCase {

	private $client;

	public function setUp(): void {
		parent::setUp();

		$this->idpUrl = getenv('IDP_URL', 'https://accounts.login00.idm.ver.sul.t-online.de/oauth2/tokens'); // url of identity provider
		$this->refreshToken = getenv('OIDC_REFRESH_TOKEN');
		$this->providername = getenv('OIDC_PROVIDERNAME', 'Telekom'); // optional
		$this->assertNotFalse($this->idpUrl, "This integration test required setting of env var IDP_URL");
		$this->assertNotFalse($this->refreshToken, "This integration test required setting of env var OIDC_REFRESH_TOKEN");

		$this->client = new Client(['allow_redirects' => ['track_redirects' => true]]);
	
		$this->providerService()
	}


	public function testBearerLogin() {
		// aquire fresh Bearer token authorized by refresh token from env
		$this->client->post($this->, ['form_params' => ['client_id' => $username, 'password' => $password, "credentialId" => '']]);


		self::assertEquals([
			[
				'name' => 'Login with nextcloudci',
				'href' => '/index.php/apps/user_oidc/login/1'
			]
		], OC_App::getAlternativeLogIns());
	}

	public function testLoginRedirect() {
		$response = $this->client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		self::assertStringStartsWith($this->oidcIdp, $headersRedirect[0]);
	}

	private function newClient() {
		$cookieJar = new CookieJar();
		$this->client = new Client(['allow_redirects' => ['track_redirects' => true], 'cookies' => $cookieJar]);
		return $this->client;
	}
	public function testLoginRedirectCallback() {
		$response = $this->client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		self::assertStringStartsWith($this->oidcIdp, $headersRedirect[0]);

		$response = $this->loginToKeycloak($headersRedirect[0], 'keycloak1', 'keycloak1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		$userId = $this->getUserId($response);
		self::assertStringStartsWith($this->baseUrl . '/index.php/apps/user_oidc/code?', $headersRedirect[0]);
		self::assertEquals($this->baseUrl . '/index.php/apps/dashboard/', $headersRedirect[1]);

		// Validate login with correct user data
		$userInfo = json_decode($userInfo->getBody()->getContents());
		self::assertEquals('keycloak1@example.com', $userInfo->ocs->data->email);
		self::assertEquals('Key Cloak 1', $userInfo->ocs->data->displayname);
		self::assertEquals(1073741824, $userInfo->ocs->data->quota->quota); // 1G

		$providerId = '1';
		$userIdHashed = hash('sha256', $providerId . '_0_' . 'aea81860-b25c-4f75-b9b5-9d632c3ba06f');
		self::assertEquals($userId, $userIdHashed);
	}

	private function loginToKeycloak($keycloakURL, $username, $password) {
		$response = $this->client->get($keycloakURL);
		$doc = new DOMDocument();
		$doc->loadHtml($response->getBody()->getContents());
		$selector = new DOMXpath($doc);
		$result = $selector->query('//form');
		$form = $result->item(0);
		$url = $form->getAttribute('action');
		libxml_clear_errors();
	}

	private function getUserId($response) {
		$content = $response->getBody()->getContents();
		$doc = new DOMDocument();
		$doc->loadHtml($content);
		$body = $doc->getElementsByTagName('head')->item(0);
		$userId = $body->getAttribute('data-user');
		libxml_clear_errors();
		return $userId;
	}

	public function testUnreachable() {
		$provider = $this->providerService->getProviderByIdentifier('nextcloudci');
		/** @var ProviderMapper $mapper */
		$mapper = \OC::$server->get(ProviderMapper::class);

		$previousDiscovery = $provider->getDiscoveryEndpoint();

		$provider->setDiscoveryEndpoint('http://unreachable/url');
		$mapper->update($provider);

		try {
			$client = new Client(['allow_redirects' => ['track_redirects' => true]]);
			$response = $client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		} catch (\Exception $e) {
			$response = $e->getResponse();
		}
		$status = $response->getStatusCode();

		$provider->setDiscoveryEndpoint($previousDiscovery);
		$mapper->update($provider);

		self::assertEquals($status, 404);
	}

	public function testNonUnique() {
		$this->providerService->setSetting(1, ProviderService::SETTING_UNIQUE_UID, '0');

		$response = $this->client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		$response = $this->loginToKeycloak($headersRedirect[0], 'keycloak1', 'keycloak1');
		$userId = $this->getUserId($response);
		self::assertEquals($userId, 'aea81860-b25c-4f75-b9b5-9d632c3ba06f');
	}

	public function testNonUniqueMapping() {
		$this->providerService->setSetting(1, ProviderService::SETTING_UNIQUE_UID, '0');
		$this->providerService->setSetting(1, ProviderService::SETTING_MAPPING_UID, 'preferred_username');

		$response = $this->client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		$response = $this->loginToKeycloak($headersRedirect[0], 'keycloak1', 'keycloak1');
		$userId = $this->getUserId($response);
		self::assertEquals($userId, 'keycloak1');
	}

	public function testUniqueMapping() {
		$this->providerService->setSetting(1, ProviderService::SETTING_MAPPING_UID, 'preferred_username');

		$response = $this->client->get($this->baseUrl . '/index.php/apps/user_oidc/login/1');
		$headersRedirect = $response->getHeader(RedirectMiddleware::HISTORY_HEADER);
		$response = $this->loginToKeycloak($headersRedirect[0], 'keycloak1', 'keycloak1');
		$userId = $this->getUserId($response);
		self::assertEquals($userId, hash('sha256', '1_0_keycloak1'));
	}
}
