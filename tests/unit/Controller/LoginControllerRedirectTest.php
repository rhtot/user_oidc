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


use OCA\UserOIDC\Controller\LoginController;
use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\TokenObtainedEvent;
use OCA\UserOIDC\Event\UserAccountChangeEvent;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\InvalidTokenException;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\Provider;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IResponse;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ICacheFactory;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;

use OCP\AppFramework\App;

use PHPUnit\Framework\TestCase;

/**
 * This testcase checks redirects in different situations
 * and special handling of Safari on call to login.
 *
 * @group Services
 */
class LoginControllerRedirectTest extends TestCase {

	public function setUp(): void {
		parent::setUp();
		$this->app = new App(Application::APP_ID);
		$this->request = $this->getMockForAbstractClass(IRequest::class);
		$this->providerMapper = $this->getMockBuilder(ProviderMapper::class)
                            ->setConstructorArgs([ $this->getMockForAbstractClass(IDBConnection::class) ])
							->getMock();
        $this->providerService = $this->getMockBuilder(ProviderService::class)
                            ->setConstructorArgs([ $this->app->getContainer()->get(IConfig::class),
                                                   $this->providerMapper])
							->getMock();        
        $this->discoveryService = $this->getMockBuilder(DiscoveryService::class)
                            ->setConstructorArgs([ $this->app->getContainer()->get(ILogger::class),
                                                    $this->getMockForAbstractClass(IClientService::class),
                                                    $this->app->getContainer()->get(ICacheFactory::class) ])
                            ->getMock();
        $this->session = $this->getMockForAbstractClass(ISession::class);
        $this->client = $this->getMockForAbstractClass(IClient::class);
		$this->response = $this->getMockForAbstractClass(IResponse::class);
        $this->clientService = $this->getMockForAbstractClass(IClientService::class);
        $this->usersession = $this->getMockForAbstractClass(IUserSession::class);
        $this->usermanager = $this->getMockForAbstractClass(IUserManager::class);
        $this->loginController = new LoginController( $this->request,
                            $this->providerMapper,
                            $this->app->getContainer()->get(ProviderService::class),
                            $this->app->getContainer()->get(UserService::class),
                            $this->discoveryService,
                            $this->app->getContainer()->get(ISecureRandom::class),
                            $this->session,
                            $this->clientService,
                            $this->app->getContainer()->get(IUrlGenerator::class),
                            $this->usersession,
                            $this->usermanager,
                            $this->app->getContainer()->get(IEventDispatcher::class),
                            $this->app->getContainer()->get(ILogger::class));
    }


    protected function setupFullLoginSequence() {

        // mock behavior that is equal for all cases
        $provider = $this->getMockBuilder(Provider::class)
            ->addMethods(['getClientId', 'getScope'])
            ->getMock();
        $provider->expects($this->once())
                ->method('getClientId')
                ->willReturn('Telekom');
        $provider->expects($this->once())
                ->method('getScope')
                ->willReturn('[openid]');
        $this->providerMapper->expects($this->once())
                            ->method('getProvider')
                            ->willReturn($provider);

        $this->discoveryService->expects($this->once())
                ->method('obtainDiscovery')
                ->willReturn( array( 'authorization_endpoint' => 'https://whatever.to.discover/authorisation' ) );
    }

	public function testLoggedInRedirect() {
        $this->usersession->expects($this->once())
            ->method('isLoggedIn')
            ->willReturn(true);
        
        $this->request->expects($this->never())
            ->method('isUserAgent');
        
        $response = $this->loginController->login(99, "https://wherever.you.go");
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertNotInstanceOf(Http\DataDisplayResponse::class, $response);       
    }


	public function testLoginRedirect() {
        $this->setupFullLoginSequence();

        $this->usersession->expects($this->once())
            ->method('isLoggedIn')
            ->willReturn(false);

        $this->request->expects($this->once())
            ->method('isUserAgent')
            ->with($this->equalTo(['/Safari/']))
            ->willReturn(false);


        $response = $this->loginController->login(99, "https://wherever.you.go");
        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertNotInstanceOf(Http\DataDisplayResponse::class, $response);    
    }

    
	public function testLoginRedirectSafari() {
        $this->setupFullLoginSequence();

        $this->usersession->expects($this->once())
            ->method('isLoggedIn')
            ->willReturn(false);

        $this->request->expects($this->at(0))
            ->method('isUserAgent')
            ->with($this->equalTo(['/Safari/']))
            ->willReturn(true);
        $this->request->expects($this->at(1))
            ->method('isUserAgent')
            ->with($this->equalTo(['/Chrome/']))
            ->willReturn(false);


        $response = $this->loginController->login(99, "https://wherever.you.go");
        $this->assertNotInstanceOf(RedirectResponse::class, $response);
        $this->assertInstanceOf(Http\DataDisplayResponse::class, $response);    
    }

    /*
	public function testCodeDefaultRedirect() {
	}

	public function testCodeProf() {
	} */
}