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


use OCP\IConfig;

use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Service\JwtService;
use OCA\UserOIDC\Service\SignatureException;
use OCA\UserOIDC\Service\InvalidTokenException;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;

use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWS;

use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;

use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;


class SamBearerTokenTest extends TestCase {

	/**
	 * @var ProviderService
	 */
	private $provider;

	/**
	 * @var JwtService
	 */
	private $jwtService;

	/**
	 * Secret for bearer access key signature and encryption
	 */
	private $bearer_secret;

	/**
	 * Real world example claims content 
	 */
	private $claimset;


	protected function setupSignedToken(array $claims, string $signKey) {
        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([
            new HS256(),
        ]);
		$jwk = new JWK([
    		'kty' => 'oct',
    		'k' => $signKey]);
		// We instantiate our JWS Builder.
		$jwsBuilder = new JWSBuilder($algorithmManager);

		$jws = $jwsBuilder->create()                               // We want to create a new JWS
                          ->withPayload(json_encode($claims))                   // We set the payload
                          ->addSignature($jwk, ['alg' => 'HS256']) // We add a signature with a simple protected header
                          ->build();  
	
		$serializer = new \Jose\Component\Signature\Serializer\CompactSerializer();
		return $serializer->serialize($jws, 0);
	}

	protected function setupSignEncryptToken(array $claims, string $secret) {
        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = new AlgorithmManager([
            new HS256(),
        ]);
		// The key encryption algorithm manager with the A256KW algorithm.
		$keyEncryptionAlgorithmManager = new AlgorithmManager([
			new PBES2HS512A256KW(),
			new RSAOAEP256(),
			new ECDHESA256KW() 
        ]);
		// The content encryption algorithm manager with the A256CBC-HS256 algorithm.
		$contentEncryptionAlgorithmManager = new AlgorithmManager([
			new A256CBCHS512(),
		]);
		// The compression method manager with the DEF (Deflate) method.
		$compressionMethodManager = new CompressionMethodManager([
			new Deflate(),
		]);


		$jwk = new JWK([
    		'kty' => 'oct',
    		'k' => $secret]);
		// We instantiate our JWS Builder.

		$jwsBuilder = new JWSBuilder($algorithmManager);
		$jws = $jwsBuilder->create()                               // We want to create a new JWS
                          ->withPayload(json_encode($claims))                   // We set the payload
                          ->addSignature($jwk, ['alg' => 'HS256']) // We add a signature with a simple protected header
                          ->build();  

		$signSerializer = new \Jose\Component\Signature\Serializer\CompactSerializer();

		// We instantiate our JWE Builder.
		$jweBuilder = new JWEBuilder(
				$keyEncryptionAlgorithmManager,
				$contentEncryptionAlgorithmManager,
				$compressionMethodManager
			);						  

		$jwe = $jweBuilder
			->create()                                         // We want to create a new JWE
			->withPayload($signSerializer->serialize($jws, 0)) // We set the payload
			->withSharedProtectedHeader([
				'alg' => 'PBES2-HS512+A256KW',                // Key Encryption Algorithm
				'enc' => 'A256CBC-HS512',                     // Content Encryption Algorithm
				'zip' => 'DEF'                                // We enable the compression (just for the example).
			])
			->addRecipient($jwk)
			->build();              // We build it

		$encryptionSerializer = new \Jose\Component\Encryption\Serializer\CompactSerializer(); // The serializer
		return $encryptionSerializer->serialize($jwe, 0);
	}


	public function setUp(): void {
		parent::setUp();

		$this->jwtService = \OC::$server->get(JwtService::class);
		$this->bearer_secret = \Base64Url\Base64Url::encode('JQ17C99A-DAF8-4E27-FBW4-GV23B043C993');
		$this->claimset = array(
			'iss' => 'sts00.idm.ver.sul.t-online.de',
			'urn:telekom.com:idm:at:subjectType' => array(
				'format' => 'urn:com:telekom:idm:1.0:nameid-format:anid',
				'realm' => 'ver.sul.t-online.de'
			),
			'acr' => 'urn:telekom:names:idm:THO:1.0:ac:classes:pwd',
			'sub' => '120049010000000007210207',
			'iat' => time(),
			'nbf' => time(),
			'exp' => time() + 7200,
			'urn:telekom.com:idm:at:authNStatements' => array(
				'urn:telekom:names:idm:THO:1.0:ac:classes:pwd' => array(
					'authenticatingAuthority' => null,
					'authNInstant' => time() )
			),
			'aud' => ['http:\\auth.magentacloud.de'],
			'jti' => 'STS-1e22a06f-790c-40fb-ad1d-6de2ddcf2431',
			'urn:telekom.com:idm:at:attributes' => [
				array( 'name' => 'client_id',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '10TVL0SAM30000004901NEXTGAME0000'),
				array( 'name' => 'displayname',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'),
				array( 'name' => 'email',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'),
				array( 'name' => 'anid',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '120049010000000007310207'),
				array( 'name' => 'd556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'domt',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'ver.sul.t-online.de'),
				array( 'name' => 'f048',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'),
				array( 'name' => 'f049',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'),
				array( 'name' => 'f051',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f460',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f467',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f468',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f469',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f471',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'f556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'),
				array( 'name' => 'f734',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'mainEmail',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'),
				array( 'name' => 's556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'),
				array( 'name' => 'usta',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1')],
			'urn:telekom.com:idm:at:version' => '1.0'
			);
	
	}

	public function testValidSignature() {
        $this->expectNotToPerformAssertions();
		$testtoken = $this->setupSignedToken($this->claimset, $this->bearer_secret);
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($testtoken, $this->bearer_secret);
		$this->jwtService->verifySignature($bearerToken, $this->bearer_secret);
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }

	public function testInvalidSignature() {
		$this->expectException(SignatureException::class);
		$testtoken = $this->setupSignedToken($this->claimset, $this->bearer_secret);
		$invalidSignToken = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
		// fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($invalidSignToken, $this->bearer_secret);
		$this->jwtService->verifySignature($bearerToken, $this->bearer_secret);
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	}

	public function testEncryptedValidSignature() {
        $this->expectNotToPerformAssertions();
		$testtoken = $this->setupSignEncryptToken($this->claimset, $this->bearer_secret);
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($testtoken, $this->bearer_secret);
		$this->jwtService->verifySignature($bearerToken, $this->bearer_secret);
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }

	public function testEncryptedInvalidEncryption() {
		$this->expectException(InvalidTokenException::class);
		$testtoken = $this->setupSignEncryptToken($this->claimset, $this->bearer_secret);
		$invalidEncryption = mb_substr($testtoken, 0, -1); // shorten sign to invalidate
		//fwrite(STDERR, '[' . $testtoken . ']');
		$bearerToken = $this->jwtService->decryptToken($invalidEncryption, $this->bearer_secret);
		$this->jwtService->verifySignature($bearerToken, $this->bearer_secret);
		$claims = $this->jwtService->decodeClaims($bearerToken);
		$this->jwtService->verifyClaims($claims, ['http://auth.magentacloud.de']);
    }


}
