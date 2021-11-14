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

use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\JwtService;
use OCA\UserOIDC\Service\SignatureException;
use OCA\UserOIDC\Service\InvalidTokenException;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class HeaderBearerTokenTest extends TokenTestCase {

	/**
	 * @var ProviderService
	 */
	private $provider;

	/**
	 * @var Backend
	 */
	private $backend;


	public function setUp(): void {
		parent::setUp();

		$app = new \OCP\AppFramework\App(Application::APP_ID);
		$this->requestMock = $this->createMock(IRequest::class);

		$this->config = $this->createMock(IConfig::class);
		$this->providerMapper = $this->createMock(ProviderMapper::class);
		$this->providerService = new ProviderService($this->config, $this->providerMapper);
		$this->backend = new Backend($app->getContainer()->get(ILogger::class),
									$this->requestMock,
									$app->getContainer()->get($this->providerMapper),
									$app->getContainer()->get($this->providerService),
									$app->getContainer()->get(UserMapper::class),
									$app->getContainer()->get(UserService::class),
									$app->getContainer()->get(DiscoveryService::class),
									$app->getContainer()->get(JwtService::class));
	}

	public function testValidSignature() {
		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$this->requestMock->expects($this->any())
						->method('getHeader')
						->with($this->equalTo(Application::OIDC_API_REQ_HEADER))
						->willReturn("Bearer " . $testtoken);
		$this->assertTrue($this->backend->isSessionActive());
		$this->assertNotEquals('', $this->backend->getCurrentUserId());
	}

	// public function testInvalidSignature() {
	// 	$this->expectException(SignatureException::class);
	// 	$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
	// 	$invalidSignToken = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
	// 	// fwrite(STDERR, '[' . $testtoken . ']');
	// 	$bearerToken = $this->jwtService->decryptToken($invalidSignToken, $this->getTestBearerSecret());
	// 	$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
	// 	$claims = $this->jwtService->decodeClaims($bearerToken);
	// 	$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	// }

	// public function testEncryptedValidSignature() {
    //     $this->expectNotToPerformAssertions();
	// 	$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
	// 	//fwrite(STDERR, '[' . $testtoken . ']');
	// 	$bearerToken = $this->jwtService->decryptToken($testtoken, $this->getTestBearerSecret());
	// 	$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
	// 	$claims = $this->jwtService->decodeClaims($bearerToken);
	// 	$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    // }

	// public function testEncryptedInvalidEncryption() {
	// 	$this->expectException(InvalidTokenException::class);
	// 	$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
	// 	$invalidEncryption = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
	// 	//fwrite(STDERR, '[' . $testtoken . ']');
	// 	$bearerToken = $this->jwtService->decryptToken($invalidEncryption, $this->getTestBearerSecret());
	// 	$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
	// 	$claims = $this->jwtService->decodeClaims($bearerToken);
	// 	$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    // }


}
