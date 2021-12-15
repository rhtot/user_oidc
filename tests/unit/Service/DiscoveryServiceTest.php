<?php
/*
 * @copyright Copyright (c) 2021 T-Systems International
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


use OCP\ILogger;
use OCP\ICacheFactory;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IResponse;

use OCP\AppFramework\App;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Db\Provider;

use PHPUnit\Framework\TestCase;

/**
 *
 *
 * @group Services
 */
class DiscoveryServiceTest extends TestCase {
	public function setUp(): void {
		parent::setUp();
		$this->app = new App(Application::APP_ID);
	
		$this->provider = $this->getMockBuilder(Provider::class)
							->addMethods(['getDiscoveryEndpoint'])
							->getMock();
		$this->client = $this->getMockForAbstractClass(IClient::class);
		$this->clientFactory = $this->getMockForAbstractClass(IClientService::class);
		$this->clientFactory->expects($this->any())
							->method('newClient')
							->willReturn($this->client);
		$this->response = $this->getMockForAbstractClass(IResponse::class);


		$this->discoveryServiceUnderTest = new DiscoveryService(
			$this->app->getContainer()->get(ILogger::class),
			$this->clientFactory,
			$this->app->getContainer()->get(ICacheFactory::class));
	}

	public function testDiscoveryCache() {
		$this->provider->expects($this->once())
								->method('getDiscoveryEndpoint')
								->willReturn('https://test.point/.well-known');

		$this->client->expects($this->once())
								->method('get')
								->with($this->equalTo('https://test.point/.well-known'))
								->willReturn($this->response);

		$this->response->expects($this->once())
								->method('getBody')
								->willReturn('{ "jwks_uri": "https://test.point/oauth2/keys" }');

		$endpoints = $this->discoveryServiceUnderTest->obtainDiscovery($this->provider);
		$this->arrayHasKey('jwks_uri', $endpoints);
		$this->assertEquals($endpoints['jwks_uri'], "https://test.point/oauth2/keys");

		$endpoints2 = $this->discoveryServiceUnderTest->obtainDiscovery($this->provider);
		$this->arrayHasKey('jwks_uri', $endpoints2);
		$this->assertEquals($endpoints2['jwks_uri'], "https://test.point/oauth2/keys");
	}



	public function testDiscoveryReCache() {
		$this->provider->expects($this->exactly(2))
								->method('getDiscoveryEndpoint')
								->willReturn('https://test.point/.well-known');

		$this->client->expects($this->exactly(2))
								->method('get')
								->with($this->equalTo('https://test.point/.well-known'))
								->willReturn($this->response);

		$this->response->expects($this->exactly(2))
								->method('getBody')
								->willReturn('{ "jwks_uri": "https://test.point/oauth2/keys" }');

		$endpoints = $this->discoveryServiceUnderTest->obtainDiscovery($this->provider, 1);
		$this->arrayHasKey('jwks_uri', $endpoints);
		$this->assertEquals($endpoints['jwks_uri'], "https://test.point/oauth2/keys");

		$this->discoveryServiceUnderTest->invalidateCache();

		$endpoints2 = $this->discoveryServiceUnderTest->obtainDiscovery($this->provider);
		$this->arrayHasKey('jwks_uri', $endpoints2);
		$this->assertEquals($endpoints2['jwks_uri'], "https://test.point/oauth2/keys");
	}

	public function testJwksCache() {
		$this->provider->expects($this->once())
								->method('getDiscoveryEndpoint')
								->willReturn('https://test.point/.well-known');

		$this->client->expects($this->at(0))
								->method('get')
								->with($this->equalTo('https://test.point/.well-known'))
								->willReturn($this->response);
		$this->response->expects($this->at(0))
								->method('getBody')
								->willReturn('{ "jwks_uri": "https://accounts.login.idm.telekom.com/oauth2/v1/certs" }');
		$this->client->expects($this->at(1))
								->method('get')
								->with($this->equalTo('https://accounts.login.idm.telekom.com/oauth2/v1/certs'))
								->willReturn($this->response);
		$this->response->expects($this->at(1))
								->method('getBody')
								->willReturn('{"keys": [{"kty":"RSA","e":"AQAB","use":"sig","kid":"1410858811","alg":"RS256","n":"nGp2v_0NmeQf62SQ38OehMaWCzGR5OW8oJNXSDRAH1Hm1MojLADKks8dnQTFqSeaiYGOSKxQfdMbC0NKIAl81OFIBBfelJeBfgEflcUwmm2lyCehEtTAfChkYagBm8Kqk6BDBqefVFBCwpRoN6lRqvgCoWYwY-7jWJDMS9iWF5YBOMTlKDa8Nl5Ihoc0CdCY64MlOLnhgmAt7YHo7KZPY0d1kSpJB6tjUg6ey6jBpvARwk7E0lIt9m2tpML3oDyxJtQurLw5_NHQFbvxf70h7XUGGqfX8Vo2YKnRUO1-HKRqoOcHKSh65wkI3-_1QwBkGnx16B-gD_iMKTnmbej3HQ"},{"kty":"EC","use":"sig","crv":"P-256","kid":"831cd9a0-cfe3-417c-99b0-23e7c8aae74e","x":"H1pUxS4o0POsRt8R3qJ1ww_ef34ItgjCM9NrkZnAi98","y":"ABzvYne-iRHHFqU2U7WfLgUsKjCnSuBkCPK3hEZLGF8","alg":"ES256"}]}');
		$jwks = $this->discoveryServiceUnderTest->obtainJWK($this->provider);
		$this->arrayHasKey('RSA', $jwks);
		$this->arrayHasKey('EC', $jwks);

		$jwks2 = $this->discoveryServiceUnderTest->obtainJWK($this->provider);
		$this->arrayHasKey('RSA', $jwks2);
		$this->arrayHasKey('EC', $jwks2);
	}

	public function testJwksReCache() {
		$this->provider->expects($this->exactly(2))
								->method('getDiscoveryEndpoint')
								->willReturn('https://test.point/.well-known');

		$this->client->expects($this->at(0))
								->method('get')
								->with($this->equalTo('https://test.point/.well-known'))
								->willReturn($this->response);
		$this->response->expects($this->at(0))
								->method('getBody')
								->willReturn('{ "jwks_uri": "https://accounts.login.idm.telekom.com/oauth2/v1/certs" }');
		$this->client->expects($this->at(1))
								->method('get')
								->with($this->equalTo('https://accounts.login.idm.telekom.com/oauth2/v1/certs'))
								->willReturn($this->response);
		$this->response->expects($this->at(1))
								->method('getBody')
								->willReturn('{"keys": [{"kty":"RSA","e":"AQAB","use":"sig","kid":"1410858811","alg":"RS256","n":"nGp2v_0NmeQf62SQ38OehMaWCzGR5OW8oJNXSDRAH1Hm1MojLADKks8dnQTFqSeaiYGOSKxQfdMbC0NKIAl81OFIBBfelJeBfgEflcUwmm2lyCehEtTAfChkYagBm8Kqk6BDBqefVFBCwpRoN6lRqvgCoWYwY-7jWJDMS9iWF5YBOMTlKDa8Nl5Ihoc0CdCY64MlOLnhgmAt7YHo7KZPY0d1kSpJB6tjUg6ey6jBpvARwk7E0lIt9m2tpML3oDyxJtQurLw5_NHQFbvxf70h7XUGGqfX8Vo2YKnRUO1-HKRqoOcHKSh65wkI3-_1QwBkGnx16B-gD_iMKTnmbej3HQ"},{"kty":"EC","use":"sig","crv":"P-256","kid":"831cd9a0-cfe3-417c-99b0-23e7c8aae74e","x":"H1pUxS4o0POsRt8R3qJ1ww_ef34ItgjCM9NrkZnAi98","y":"ABzvYne-iRHHFqU2U7WfLgUsKjCnSuBkCPK3hEZLGF8","alg":"ES256"}]}');
        $this->client->expects($this->at(2))
								->method('get')
								->with($this->equalTo('https://test.point/.well-known'))
								->willReturn($this->response);
		$this->response->expects($this->at(2))
								->method('getBody')
								->willReturn('{ "jwks_uri": "https://accounts.login.idm.telekom.com/oauth2/v2/certs" }');
		$this->client->expects($this->at(3))
								->method('get')
								->with($this->equalTo('https://accounts.login.idm.telekom.com/oauth2/v2/certs'))
								->willReturn($this->response);
		$this->response->expects($this->at(3))
								->method('getBody')
								->willReturn('{"keys": [{"kty":"RSA","e":"AQAB","use":"sig","kid":"1410858811","alg":"RS256","n":"nGp2v_0NmeQf62SQ38OehMaWCzGR5OW8oJNXSDRAH1Hm1MojLADKks8dnQTFqSeaiYGOSKxQfdMbC0NKIAl81OFIBBfelJeBfgEflcUwmm2lyCehEtTAfChkYagBm8Kqk6BDBqefVFBCwpRoN6lRqvgCoWYwY-7jWJDMS9iWF5YBOMTlKDa8Nl5Ihoc0CdCY64MlOLnhgmAt7YHo7KZPY0d1kSpJB6tjUg6ey6jBpvARwk7E0lIt9m2tpML3oDyxJtQurLw5_NHQFbvxf70h7XUGGqfX8Vo2YKnRUO1-HKRqoOcHKSh65wkI3-_1QwBkGnx16B-gD_iMKTnmbej3HQ"},{"kty":"EC","use":"sig","crv":"P-256","kid":"831cd9a0-cfe3-417c-99b0-23e7c8aae74e","x":"H1pUxS4o0POsRt8R3qJ1ww_ef34ItgjCM9NrkZnAi98","y":"ABzvYne-iRHHFqU2U7WfLgUsKjCnSuBkCPK3hEZLGF8","alg":"ES256"}]}');
		$jwks = $this->discoveryServiceUnderTest->obtainJWK($this->provider);
		$this->arrayHasKey('RSA', $jwks);
		$this->arrayHasKey('EC', $jwks);

		$this->discoveryServiceUnderTest->invalidateCache();

		$jwks2 = $this->discoveryServiceUnderTest->obtainJWK($this->provider);
        $this->arrayHasKey('RSA', $jwks2);
		$this->arrayHasKey('EC', $jwks2);
	}

}
