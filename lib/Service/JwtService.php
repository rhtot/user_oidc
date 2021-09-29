<?php
/*
 * @copyright Copyright (c) 2021 Bernd Rederlechner <bernd.rederlechner@t-systems.com>
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

namespace OCA\UserOIDC\Service;

use OCP\ILogger;
use OCP\AppFramework\Utility\ITimeFactory;

use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Db\Provider;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;

use Jose\Component\Core\JWK;

use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker;

class JwtService {

    /** @var ILogger */
	private $logger;

	/** @var ITimeFactory */
	private $timeFactory;

    public function __construct(ILogger $logger,
                                ITimeFactory $timeFactory,
                                ProviderService $providerService) {
        $this->logger = $logger;
        $this->timeFactory = $timeFactory;
        $this->providerService = $providerService;
        
        // The key encryption algorithm manager with the A256KW algorithm.
        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new PBES2HS512A256KW(),
            new RSAOAEP256(),
            new ECDHESA256KW() ]);
        
        // The content encryption algorithm manager with the A256CBC-HS256 algorithm.
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256CBCHS512(),
        ]);
        
        // The compression method manager with the DEF (Deflate) method.
        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);
        
        // We instantiate our JWE Decrypter.
        $this->jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        // The serializer manager. We only use the JWE Compact Serialization Mode.
        $this->serializerManager = new \Jose\Component\Signature\Serializer\JWSSerializerManager([
            new \Jose\Component\Signature\Serializer\CompactSerializer(),
            ]);


        $this->encryptionSerializerManager = new \Jose\Component\Encryption\Serializer\JWESerializerManager([
            new \Jose\Component\Encryption\Serializer\CompactSerializer(),
            ]);
        
    }
    
    /**
     * Implement JOSE decryption for SAM3 tokens
     */
    public function decryptToken(Provider $provider, string $token) : string {
        // trusted authenticator and myself share the client secret,
        // so use it is used for encrypted web tokens
        $clientSecret = JWK::create([
            'kty' => 'oct',
            'k' => $provider->getClientSecret()
            //'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g',
        ]);

        // We try to load the token.
        $jwe = $this->encryptionSerializerManager->unserialize($token);
        
        // We decrypt the token. This method does NOT check the header.
        return $this->jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
    }

    /**
     * Get claims (even before verification to access e.g. aud standard field ...)
     * Transform them in a format compatible with id_token representation.
     */
    public function decodeClaims(Provider $provider, string $token) : object {
        $jws = $this->serializerManager->unserialize($token);
        $this->logger->debug("Telekom SAM3 access token: " . $jws->getPayload());
        
        $samContent = json_decode($jws->getPayload(), false);
        $claimArray = $samContent->{'urn:telekom.com:idm:at:attributes'};

        // adapt into OpenId id_token format (as far as possible)
        $audience = array_filter($claimArray, function ($kv) { return (strcmp($kv->name, 'client_id') == 0) ? true : false; } );
        $payload = array(
            'aud' => [ $audience[0]->value ],
            'iss' => $samContent->iss,
            'sub' => $samContent->sub,
            'iat' => $samContent->iat,
            'nbf' => $samContent->nbf,
            'exp' => $samContent->exp,
        ); 
        // remap all the custom claims
        foreach ( $claimArray as $claimKeyValue ) {
            $payload['urn:telekom.com:' . $claimKeyValue->name] = $claimKeyValue->value;
        }

        $claims = (object)$payload;
        $this->logger->debug("Adapted OpenID-like token; " . json_encode($claims));
        return $claims;
    }

    public function verifyToken(Provider $provider, object $claims) {
        $timestamp = $this->timeFactory->getTime();
        $leeway = 60;

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($claims->nbf) && $claims->nbf > ($timestamp + $leeway)) {
            throw new InvalidTokenException(
                'Cannot handle token prior to ' . \date(DateTime::ISO8601, $claims->nbf)
            );
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($claims->iat) && $claims->iat > ($timestamp + $leeway)) {
            throw new InvalidTokenException(
                'Cannot handle token prior to ' . \date(DateTime::ISO8601, $claims->iat)
            );
        }

        // Check if this token has expired.
        if (isset($claims->exp) && ($timestamp - $leeway) >= $claims->exp) {
            throw new InvalidTokenException('Expired token');
        }
    }

}
