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


use OCP\ILogger;
use OCP\IRequest;
use OCP\IConfig;

use OCA\UserOIDC\AppInfo\Application;

use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Db\ProviderMapper;

use OCA\UserOIDC\Command\UpsertProvider;
use Symfony\Component\Console\Tester\CommandTester;


use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class BearerSettingsTest extends TestCase {
        /**
	 * @var ProviderService
	 */
	private $provider;

	/**
	 * @var ILogger
	 */
	private $logger;

	/**
	 * @var IConfig;
	 */
	private $config;

	public function setUp(): void {
		parent::setUp();

		$app = new \OCP\AppFramework\App(Application::APP_ID);
		$this->requestMock = $this->createMock(IRequest::class);

		$this->config = $this->createMock(IConfig::class);
		// $this->config->expects(self::any())
		// 	->method('getAppValue')
		// 	->willReturnMap([
		// 		[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_UID, 'sub', 'uid'],
		// 		[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_DISPLAYNAME, 'urn:telekom.com:displayname', 'dn'],
		// 		[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_EMAIL, 'urn:telekom.com:mainEmail', 'mail'],
		// 		[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_MAPPING_QUOTA, 'quota', '1g'],
		// 		[Application::APP_ID, 'provider-2-' . ProviderService::SETTING_UNIQUE_UID, '0', '0'],
		// 	]);


		$this->providerMapper = $this->createMock(ProviderMapper::class);
		$providers = [
			new \OCA\UserOIDC\Db\Provider(),
		];
		$providers[0]->setId(1);
		$providers[0]->setIdentifier('Fraesbook');

		$this->providerMapper->expects(self::any())
			->method('getProviders')
			->willReturn($providers);

		$this->providerService = $this->getMockBuilder(ProviderService::class)
                                ->setConstructorArgs([ $this->config, $this->providerMapper])
                                ->onlyMethods(['getProviderByIdentifier'])         
                                ->getMock();
    }

    public function testCommandAddProvider() {
        $provider = $this->getMockBuilder(Provider::class)
                            ->addMethods(['getId'])
                            ->getMock();

        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);

        $this->providerService->expects($this->once())
                                ->method('getProviderByIdentifier')
                                ->with($this->equalTo('Telekom'))
                                ->willReturn(null);
        $this->providerMapper->expects($this->once())
                                ->method('createOrUpdateProvider')
                                ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                        $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                        $this->equalTo('openid email profile'))
                ->willReturn($provider);

        $this->config->expects($this->exactly(5))
                ->method('setAppValue')
                ->withConsecutive(
                        [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_UNIQUE_UID), 
                                $this->equalTo('0') ],
                        [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_DISPLAYNAME), 
                            $this->equalTo('urn:telekom.com:displayname')],
                        [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_EMAIL),
                            $this->equalTo('urn:telekom.com:mainEmail')],
                        [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_QUOTA), 
                            $this->equalTo('quota')],
                        [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_UID), 
                                $this->equalTo('sub')]
                );
            
        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--clientid' => '10TVL0SAM30000004901NEXTMAGENTACLOUDTEST',
            '--clientsecret' => 'clientsecret***',
            '--bearersecret'=> 'bearersecret***',
            '--discoveryuri' => 'https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration',
            '--scope' => 'openid email profile',
            '--unique-uid' => '0',
            '--mapping-display-name' => 'urn:telekom.com:displayname',
            '--mapping-email' => 'urn:telekom.com:mainEmail', 
            '--mapping-quota' => 'quota', 
            '--mapping-uid' =>  'sub',
        ));


        //$output = $commandTester->getOutput();
        //$this->assertContains('done', $output);
    }

    public function testCommandUpdateFull() {
        $provider = $this->getMockBuilder(Provider::class)
                    ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                    ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->never())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->never())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->never())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->never())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->never())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004902NEXTMAGENTACLOUDTEST'), $this->equalTo('client*secret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('bearer*secret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-unknown/openid-configuration'), 
                                    $this->equalTo('openid profile'))
                            ->willReturn($provider);

        $this->config->expects($this->exactly(5))
                            ->method('setAppValue')
                        ->withConsecutive(
                                [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_UNIQUE_UID), 
                                        $this->equalTo('1') ],
                                [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_DISPLAYNAME), 
                                    $this->equalTo('urn:telekom.com:displaykrame')],
                                [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_EMAIL),
                                    $this->equalTo('urn:telekom.com:mainDemail')],
                                [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_QUOTA), 
                                    $this->equalTo('quotas')],
                                [$this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_MAPPING_UID), 
                                        $this->equalTo('flop')]
                        );
  
        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array(
                'identifier' => 'Telekom',
                '--clientid' => '10TVL0SAM30000004902NEXTMAGENTACLOUDTEST',
                '--clientsecret' => 'client*secret***',
                '--bearersecret'=> 'bearer*secret***',
                '--discoveryuri' => 'https://accounts.login00.idm.ver.sul.t-online.de/.well-unknown/openid-configuration',
                '--scope' => 'openid profile',
                '--mapping-display-name' => 'urn:telekom.com:displaykrame',
                '--mapping-email' => 'urn:telekom.com:mainDemail', 
                '--mapping-quota' => 'quotas', 
                '--mapping-uid' =>  'flop',
                '--unique-uid' => '1'
                ));        
        }

        public function testCommandUpdateSingleClientId() {
                $provider = $this->getMockBuilder(Provider::class)
                        ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                        ->getMock();
                $provider->expects($this->any())
                        ->method('getId')
                        ->willReturn(2);
                $provider->expects($this->never())
                        ->method('getClientId')
                        ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
                $provider->expects($this->once())
                        ->method('getClientSecret')
                        ->willReturn('clientsecret***');
                $provider->expects($this->once())
                        ->method('getBearerSecret')
                        ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
                $provider->expects($this->once())
                        ->method('getDiscoveryEndpoint')
                        ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
                $provider->expects($this->once())
                        ->method('getScope')
                        ->willReturn('openid email profile');
    
                $this->providerService->expects($this->once())
                                    ->method('getProviderByIdentifier')
                                    ->with($this->equalTo('Telekom'))
                                    ->willReturn($provider);
                $this->providerMapper->expects($this->once())
                                    ->method('createOrUpdateProvider')
                                    ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004903NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                            $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                            $this->equalTo('openid email profile'))
                                    ->willReturn($provider);
        
                $this->config->expects($this->never())
                                ->method('setAppValue');
        
                $command = new UpsertProvider($this->providerService, $this->providerMapper);
                $commandTester = new CommandTester($command);
        
                $commandTester->execute(array(
                    'identifier' => 'Telekom',
                    '--clientid' => '10TVL0SAM30000004903NEXTMAGENTACLOUDTEST',
                ));        
    }


    public function testCommandUpdateSingleClientSecret() {
        $provider = $this->getMockBuilder(Provider::class)
                ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->never())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->once())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->once())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->once())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('***clientsecret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                    $this->equalTo('openid email profile'))
                            ->willReturn($provider);

        $this->config->expects($this->never())
                        ->method('setAppValue');

        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--clientsecret' => '***clientsecret***',
        ));        
}

public function testCommandUpdateSingleBearerSecret() {
        $provider = $this->getMockBuilder(Provider::class)
                ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->once())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->never())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->once())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->once())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('***bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                    $this->equalTo('openid email profile'))
                            ->willReturn($provider);

        $this->config->expects($this->never())
                        ->method('setAppValue');

        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--bearersecret' => '***bearersecret***',
        ));        
}

public function testCommandUpdateSingleDiscoveryEndpoint() {
        $provider = $this->getMockBuilder(Provider::class)
                ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->once())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->once())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->never())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->once())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-unknown/openid-configuration'), 
                                    $this->equalTo('openid email profile'))
                            ->willReturn($provider);

        $this->config->expects($this->never())
                        ->method('setAppValue');

        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--discoveryuri' => 'https://accounts.login00.idm.ver.sul.t-online.de/.well-unknown/openid-configuration',
        ));        
}

public function testCommandUpdateSingleScope() {
        $provider = $this->getMockBuilder(Provider::class)
                ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->once())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->once())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->once())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->never())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                    $this->equalTo('openid profile'))
                            ->willReturn($provider);

        $this->config->expects($this->never())
                        ->method('setAppValue');

        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--scope' => 'openid profile',
        ));        
}

public function testCommandUpdateSingleUniqueUid() {
        $provider = $this->getMockBuilder(Provider::class)
                ->addMethods(['getId', 'getClientId', 'getClientSecret', 'getBearerSecret', 'getDiscoveryEndpoint', 'getScope'])
                ->getMock();
        $provider->expects($this->any())
                ->method('getId')
                ->willReturn(2);
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST');
        $provider->expects($this->once())
                ->method('getClientSecret')
                ->willReturn('clientsecret***');
        $provider->expects($this->once())
                ->method('getBearerSecret')
                ->willReturn(\Base64Url\Base64Url::encode('bearersecret***'));
        $provider->expects($this->once())
                ->method('getDiscoveryEndpoint')
                ->willReturn('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration');
        $provider->expects($this->once())
                ->method('getScope')
                ->willReturn('openid email profile');

        $this->providerService->expects($this->once())
                            ->method('getProviderByIdentifier')
                            ->with($this->equalTo('Telekom'))
                            ->willReturn($provider);
        $this->providerMapper->expects($this->once())
                            ->method('createOrUpdateProvider')
                            ->with($this->equalTo('Telekom'), $this->equalTo('10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'), $this->equalTo('clientsecret***'),
                                    $this->equalTo(\Base64Url\Base64Url::encode('bearersecret***')), $this->equalTo('https://accounts.login00.idm.ver.sul.t-online.de/.well-known/openid-configuration'), 
                                    $this->equalTo('openid email profile'))
                            ->willReturn($provider);

        $this->config->expects($this->once())
                        ->method('setAppValue')
                        ->with($this->equalTo(Application::APP_ID), $this->equalTo('provider-2-' . ProviderService::SETTING_UNIQUE_UID), 
                        $this->equalTo('1') );
        $command = new UpsertProvider($this->providerService, $this->providerMapper);
        $commandTester = new CommandTester($command);

        $commandTester->execute(array(
            'identifier' => 'Telekom',
            '--unique-uid' => '1',
        ));        
}


}