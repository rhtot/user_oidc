<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2020, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.de>
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
 *̉
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\UserOIDC\Controller;

use OCP\IRequest;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserSession;

use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Controller;

use OCA\UserOIDC\AppInfo\Application;

/**
 * Simple endpoint to easily testing bearer implementation
 * from outside server installation
 */
class BearerTestController extends Controller {
	
	/** @var ILogger */
	private $logger;

	/** @var IUserSession */
	private $userSession;

	public function __construct($appName,
                            IRequest $request,
							ILogger $logger,
							IUserSession $userSession) {
        parent::__construct($appName, $request);
        $this->logger = $logger;
		$this->userSession = $userSession;
	}
	
	/**
	 * Evaluate bearer token and return the userid
	 * on success.
	 *
	 * Backend.php will produce the error on fail.
	 *
     * @NoCSRFRequired
	 * @NoAdminRequired
	 */
	public function username() {
		// check if installation has Backend.php not installed, but this controller
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);
		// Authorization is also send for other tokens, so make sure the handling here only goes for bearer
        if (!preg_match('/^\s*bearer\s+/i', $headerToken)) {
			return new JSONResponse(['Not a bearer authorization'], Http::STATUS_UNAUTHORIZED);
		}

        $username = $this->userSession->getUser()->getUID();
        return new JSONResponse([ 'username' => $username ], Http::STATUS_OK);
	}
}
