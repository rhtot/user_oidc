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

use OCA\UserOIDC\AppInfo\Application;

use OCP\AppFramework\App;

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
 * You can call this test with:
 * ```
 * cd apps/user_oidc
 * NMC_URL="https://dev1.next.magentacloud.de" OIDC_REFRESH_TOKEN="<from previous SAM authorisation>" OIDC_CLIENTID="10TVL0SAM300000049***"
 * OIDC_CLIENTSECRET="FGW2D9BB-***" phpunit --stderr --bootstrap tests/bootstrap.php tests/integration/Bearer --filter=ValidBearerFromRefreshTokenTest
 * ```
 *
 * @group Bearer
 */
class ValidBearerFromRefreshTokenTest extends TestCase {
	protected $client;

	/** @var string */
	protected $identUrl;

	/** @var App */
	protected $app;

	public function setUp(): void {
		parent::setUp();
		$this->app = new App(Application::APP_ID);

		$this->refreshToken = getenv('OIDC_REFRESH_TOKEN');
		$this->clientId = getenv('OIDC_CLIENTID');
		$this->clientSecret = getenv('OIDC_CLIENTSECRET');
		$this->nmcUrl = getenv('NMC_URL') ?: 'https://dev1.next.magentacloud.de';
		$this->identUrl = getenv('IDP_URL') ?: 'https://accounts.login00.idm.ver.sul.t-online.de/oauth2/tokens'; // url of identity provider

		//$this->assertNotFalse($this->identUrl, "This integration test required setting of env var IDP_URL");
		$this->assertNotFalse($this->refreshToken, "This integration test required setting of env var OIDC_REFRESH_TOKEN");
		$this->assertNotFalse($this->clientId, "This integration test required setting of env var OIDC_CLIENTID");
		$this->assertNotFalse($this->clientSecret, "This integration test required setting of env var OIDC_CLIENTSECRET");

		$this->client = new Client(['allow_redirects' => ['track_redirects' => true]]);
	}

	public function testEmptyBearer() {
        $this->expectException(GuzzleHttp\Exception\ClientException::class); // see server log for details atm, better status handling todo
		$userRequestUrl = $this->nmcUrl . "/apps/user_oidc/bearertest";
		$rawUserResult = $this->client->get($userRequestUrl,
				[   'headers' => [
					"OCS-APIRequest" => "true",
					'Accept' => 'application/json',
					'Authorization' => 'Bearer     '
				],
				]);
		//fwrite(STDERR, $rawUserResult->getBody()->getContents());
		$userResult = json_decode($rawUserResult->getBody()->getContents());
	}

	public function testNoAuthorization() {
        $this->expectException(GuzzleHttp\Exception\ClientException::class); // see server log for details atm, better status handling todo
		$userRequestUrl = $this->nmcUrl . "/apps/user_oidc/bearertest";
		$rawUserResult = $this->client->get($userRequestUrl,
                    [   'headers' => [
                        "OCS-APIRequest" => "true",
                        'Accept' => 'application/json',
                    ],
				]);
		//fwrite(STDERR, $rawUserResult->getBody()->getContents());
		$userResult = json_decode($rawUserResult->getBody()->getContents());
	}



	/**
	 * Aquire a token for the user and query Nextcloud user account info
	 *
	 * The corresponding curl commands are:
	 * curl -X POST "https://accounts.login00.idm.ver.sul.t-online.de/oauth2/tokens" -H "Accept: application/json"\
	 *   -H "Content-Type: application/x-www-form-urlencoded"\
	 *   -d "client_id=...&client_secret=...&&grant_type=refresh_token&scope=magentacloud&refresh_token=RT2:..."
	 *
	 * curl -i -H "OCS-APIRequest: true" -H "Authorization:Bearer ..." -X GET 'https://dev2.next.magentacloud.de/ocs/v1.php/cloud/users/anid'
	 */
	public function testBearerLoginUserData() {
		// aquire fresh Bearer token authorized by refresh token from env
		$rawresult = $this->client->post($this->identUrl,
					[   'headers' => [
						'Accept' => 'application/json',
					],
						'form_params' => [ 'client_id' => $this->clientId,
							'client_secret' => $this->clientSecret,
							'grant_type' => 'refresh_token',
							'scope' => 'magentacloud',
							'refresh_token' => $this->refreshToken] ]);
		$result = json_decode($rawresult->getBody()->getContents());
		
		$bearerToken = $result->access_token;
        //fwrite(STDERR, PHP_EOL . $bearerToken);
		$userRequestUrl = $this->nmcUrl . "/apps/user_oidc/bearertest";
		$rawUserResult = $this->client->get($userRequestUrl,
					[   'headers' => [
						"OCS-APIRequest" => "true",
						'Accept' => 'application/json',
						'Authorization' => 'Bearer ' . $bearerToken
					],
					]);
		//fwrite(STDERR, $rawUserResult->getBody()->getContents());
		$userResult = json_decode($rawUserResult->getBody()->getContents());
        $this->assertObjectHasAttribute('username', $userResult);
        $this->assertEquals(24, strlen($userResult->username));
        $this->assertStringStartsWith("120049", $userResult->username);
	}
}
