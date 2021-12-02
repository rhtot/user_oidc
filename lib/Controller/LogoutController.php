<?php

/** @noinspection AdditionOperationOnArraysInspection */

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2020, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\UserOIDC\Controller;

use OCA\UserOIDC\AppInfo\Application;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\ILogger;
use OCP\IRequest;

class LogoutController extends Controller {

    /** @var ILogger */
	private $logger;

    /** @var ISession */
	private $session;

    /** @var IUserSession */
	private $userSession;

    /** @var ProviderService */
	private $providerService;

	/** @var DiscoveryService */
	private $discoveryService;


	public function __construct(
		IRequest $request,
		ILogger $logger,
        ISession $session,
        IUserSession $userSession,
        ProviderService $providerService,
		DiscoveryService $discoveryService
	) {
		parent::__construct(Application::APP_ID, $request);

		$this->logger = $logger;
        $this->session = $session;
        $this->userSession = $userSession;
        $this->providerService = $providerService;
        $this->discoverService = $discoveryService;
	}

    protected function defaultLoginPage() {
        $loginRedirect = $this->session->get(self::REDIRECT_AFTER_LOGIN);
        if ($loginRedirect == null) {
            $loginRedirect = \OC_Util::getDefaultPageUrl();
        }
        return $loginRedirect;
    }

    protected function ssoLogoutPage() {
        $provider = 'Telekom';
        $provider = $this->providerService->getProviderByIdentifier($provider);
        if ( $provider != null ) {
            try {
                $discovery = $this->discoveryService->obtainDiscovery($provider);
            } catch (\Exception $e) {
                $this->logger->error('Could not reach provider at URL ' . $provider->getDiscoveryEndpoint());
                return new RedirectResponse($this->defaultLoginPage());
            }
            $ssoPage = $discovery['logout_endpoint'];
            $this->logger->debug("Logout with endpoint " . $ssoPage);
            if (!is_null($ssoPage)) {
                return new RedirectResponse($ssoPage);
            } else {
                return new RedirectResponse($this->defaultLoginPage());
            }
        } else {
            // TODO: lacking a good strategy for multiple providers yet
            return new RedirectResponse($this->defaultLoginPage());
        }

    }


	/**
	 * @NoCSRFRequired
     * @UseSession
     */
	public function sessionlogout() {
        $loginToken = $this->request->getCookie('nc_token');
		if (!is_null($loginToken)) {
			$this->config->deleteUserValue($this->userSession->getUser()->getUID(), 'login_token', $loginToken);
		}
		$this->userSession->logout();

		$this->session->set('clearingExecutionContexts', '1');
		$this->session->close();

        // TODO: for now, we only support logout with 'Telekom' provider
        $response = $this->ssoLogoutPage();

		if (!$this->request->isUserAgent([Request::USER_AGENT_CHROME, Request::USER_AGENT_ANDROID_MOBILE_CHROME])) {
			$response->addHeader('Clear-Site-Data', '"cache", "storage"');
		}
        return $response;
    }

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 */
	public function logout($logoutToken = '') {
        // TODO: we have no real usecase for Backchannel logout yet.

        // If we need to implement it, we have to catch the session_token from OepID web login
        // and cache it for the associated userid because the backchannel does not have any
        // other session information.
        
        // for details, see 
        // https://accounts.login.idm.telekom.com/devguide/telekom_login/OpenIDConnectBackChannelLogout.html
        // tbs2014/tbs2014
        $this->logger->debug("Backchannel logout received: " . $logoutToken);
        return new JSONResponse();  
	}
}
