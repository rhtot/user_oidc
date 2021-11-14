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

use OCP\IConfig;

use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Service\JwtService;
use OCA\UserOIDC\Service\SignatureException;
use OCA\UserOIDC\Service\InvalidTokenException;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;


class SamBearerTokenTest extends TokenTestCase {

	/**
	 * @var ProviderService
	 */
	private $provider;


	/**
	 * Secret for bearer access key signature and encryption
	 */
	private $getTestBearerSecret();

	public function setUp(): void {
		parent::setUp();

		$this->getTestBearerSecret() = \Base64Url\Base64Url::encode('JQ17C99A-DAF8-4E27-FBW4-GV23B043C993');
	}

	public function testValidSignature() {
        $this->expectNotToPerformAssertions();
		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($testtoken, $this->getTestBearerSecret());
		$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }

	public function testInvalidSignature() {
		$this->expectException(SignatureException::class);
		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$invalidSignToken = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
		// fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($invalidSignToken, $this->getTestBearerSecret());
		$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	}

	public function testEncryptedValidSignature() {
        $this->expectNotToPerformAssertions();
		$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($testtoken, $this->getTestBearerSecret());
		$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }

	public function testEncryptedInvalidEncryption() {
		$this->expectException(InvalidTokenException::class);
		$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$invalidEncryption = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($invalidEncryption, $this->getTestBearerSecret());
		$this->jwtService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }


}
