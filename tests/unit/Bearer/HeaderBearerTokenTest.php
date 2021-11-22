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

namespace OCA\UserOIDC\UnitTest;

use OCA\UserOIDC\TestHelper\TokenTestCase;

use OCP\ILogger;
use OCP\IRequest;
use OCP\IConfig;

use OCA\UserOIDC\AppInfo\Application;


use OCA\UserOIDC\User\Backend;

//use OCA\UserOIDC\Db\User;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\JwtService;
use OCA\UserOIDC\Event\UserAccountChangeResult;

class HeaderBearerTokenTest extends TokenTestCase {

	/**
	 * @var ProviderService
	 */
	private $provider;

	/**
	 * @var UserService
	 */
	private $userService;

	/**
	 * @var Backend
	 */
	private $backend;

	/**
	 * @var IConfig;
	 */
	private $config;

	public function setUp(): void {
		parent::setUp();

		$app = new \OCP\AppFramework\App(Application::APP_ID);
		$this->requestMock = $this->createMock(IRequest::class);

		$this->config = $this->createMock(IConfig::class);
		$this->config->expects(self::any())
			->method('getAppValue')
			->willReturnMap([
				[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_UID, 'sub', 'uid'],
				[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_DISPLAYNAME, 'urn:telekom.com:displayname', 'dn'],
				[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_EMAIL, 'urn:telekom.com:mainEmail', 'mail'],
				[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_QUOTA, 'quota', '1g'],
				[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_UNIQUE_UID, '0', '0'],
			]);


		$this->providerMapper = $this->createMock(ProviderMapper::class);
		$providers = [
			new \OCA\UserOIDC\Db\Provider(),
			new \OCA\UserOIDC\Db\Provider()
		];
		$providers[0]->setId(1);
		$providers[0]->setIdentifier('Fraesbook');
		$providers[1]->setId(2);
		$providers[1]->setIdentifier('Telekom');
		$providers[1]->setClientId('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
		$providers[1]->setClientSecret('clientsecret***');
		$providers[1]->setBearerSecret('bearersecret***');
		$providers[1]->setDiscoveryEndpoint('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');

		$this->providerMapper->expects(self::any())
			->method('getProviders')
			->willReturn($providers);

		$this->providerService = new ProviderService($this->config, $this->providerMapper);
		
		$this->userService = $this->createMock(UserService::class);
		$this->userService->expects($this->any())
			->method('determineUID')
			->willReturn('1200490100000000100XXXXX');
		$this->userService->expects($this->any())
			->method('determineDisplayname')
			->willReturn('nmc01');
		$this->userService->expects($this->any())
			->method('determineEmail')
			->willReturn('nmc01@ver.sul.t-online.de');
		$this->userService->expects($this->any())
			->method('determineQuota')
			->willReturn('1TB');


		$this->backend = new Backend($app->getContainer()->get(ILogger::class),
								$this->requestMock,
								$this->providerMapper,
								$this->providerService,
								$app->getContainer()->get(UserMapper::class),
								$this->userService,
								$app->getContainer()->get(DiscoveryService::class),
								$app->getContainer()->get(JwtService::class));
	}

	public function testValidSignature() {
		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$this->requestMock->expects($this->any())
						->method('getHeader')
						->with($this->equalTo(Application::OIDC_API_REQ_HEADER))
						->willReturn("Bearer " . $testtoken);
		$this->userService->expects($this->once())
						->method("changeUserAccount")
						->willReturn(new UserAccountChangeResult(true, "Created"));
			
		$this->assertTrue($this->backend->isSessionActive());
		$this->assertEquals('1200490100000000100XXXXX', $this->backend->getCurrentUserId());
	}

	public function testInvalidSignature() {
		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$invalidSignToken = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
		$this->requestMock->expects($this->any())
						->method('getHeader')
						->with($this->equalTo(Application::OIDC_API_REQ_HEADER))
						->willReturn("Bearer " . $invalidSignToken);

		$this->assertTrue($this->backend->isSessionActive());
		$this->assertEquals('', $this->backend->getCurrentUserId());
	}

	public function testEncryptedValidSignature() {
		$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$this->requestMock->expects($this->any())
						->method('getHeader')
						->with($this->equalTo(Application::OIDC_API_REQ_HEADER))
						->willReturn("Bearer " . $testtoken);
		
        $result = new UserAccountChangeResult(true, "Created");
        $this->assertTrue($result->isAccessAllowed());
        $this->assertEquals('Created', $result->getReason());
        $this->assertNull($result->getRedirectUrl());

        $this->userService->expects($this->once())
						->method("changeUserAccount")
						->willReturn($result);

		$this->assertTrue($this->backend->isSessionActive());
		$this->assertEquals('1200490100000000100XXXXX', $this->backend->getCurrentUserId());
	}

	public function testEncryptedInvalidSignature() {
		$invalidEncToken = $this->setupSignEncryptToken($this->getRealExampleClaims(),
								$this->getTestBearerSecret(), true);
		$this->requestMock->expects($this->any())
						->method('getHeader')
						->with($this->equalTo(Application::OIDC_API_REQ_HEADER))
						->willReturn("Bearer " . $invalidEncToken);

		$this->assertTrue($this->backend->isSessionActive());
		$this->assertEquals('', $this->backend->getCurrentUserId());
	}
}
