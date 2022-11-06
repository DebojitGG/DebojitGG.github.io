<?php
/**
 * SocialIntegration_Providers_Facebook provider adapter based on OAuth2 protocol
 *
 * SocialIntegration_Providers_Facebook use the Facebook PHP SDK created by Facebook
 *
 * http://hybridauth.sourceforge.net/userguide/IDProvider_info_Facebook.html
 */

App::import('Lib/SocialIntegration', 'SocialIntergration');

class SocialIntegration_Providers_Facebook extends SocialIntergration {

	/**
	 * default permissions, and a lot of them. You can change them from the configuration by setting the scope to what you want/need
	 * {@inheritdoc}
	 */
	public $scope = "email, user_about_me, user_birthday, user_hometown, user_location, user_website, read_stream, publish_actions, read_custom_friendlists";
        public $sdk_version = '5.0.0';
	/**
	 * Provider API client
	 * @var Facebook
	 */
	public $api;

	/**
	 * {@inheritdoc}
	 */
	function initialize() {
		require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook_v5/autoload.php";
		
		if (!$this->config["keys"]["id"] || !$this->config["keys"]["secret"]) {
			throw new Exception("Your application id and secret are required in order to connect to {$this->providerId}.", 4);
		}
		if (isset($this->config['scope']))
		{
			$this->scope = $this->config['scope'];
		}
		/*if (!class_exists('FacebookApiException', false)) {
			require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook/base_facebook.php";
			require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook/facebook.php";
		}*/

		if (isset(SocialIntegration_Auth::$config["proxy"])) {
			BaseFacebook::$CURL_OPTS[CURLOPT_PROXY] = SocialIntegration_Auth::$config["proxy"];
		}

		$trustForwarded = isset($this->config['trustForwarded']) ? (bool) $this->config['trustForwarded'] : false;
		$this->api = new Facebook\Facebook([
				'app_id' =>  $this->config["keys"]["id"],
				'app_secret' => $this->config["keys"]["secret"],
				'default_graph_version' => 'v4.0'
		]);
		//$this->api = new Facebook(array('appId' => $this->config["keys"]["id"], 'secret' => $this->config["keys"]["secret"], 'trustForwarded' => $trustForwarded));

		if ($this->token("access_token")) {
			$this->api->setDefaultAccessToken($this->token("access_token"));
			/*$this->api->setAccessToken($this->token("access_token"));
			$this->api->setExtendedAccessToken();
			$access_token = $this->api->getAccessToken();

			if ($access_token) {
				$this->token("access_token", $access_token);
				$this->api->setAccessToken($access_token);
			}

			$this->api->setAccessToken($this->token("access_token"));*/
		}

		//$this->api->getUser();
	}

	/**
	 * {@inheritdoc}
	 */
	function loginBegin() {
		$parameters = array("scope" => $this->scope, "redirect_uri" => $this->endpoint, "display" => "page");
		$optionals = array("scope", "redirect_uri", "display", "auth_type");

		foreach ($optionals as $parameter) {
			if (isset($this->config[$parameter]) && !empty($this->config[$parameter])) {
				$parameters[$parameter] = $this->config[$parameter];

				//If the auth_type parameter is used, we need to generate a nonce and include it as a parameter
				if ($parameter == "auth_type") {
					$nonce = md5(uniqid(mt_rand(), true));
					$parameters['auth_nonce'] = $nonce;

					SocialIntegration_Auth::storage()->set('fb_auth_nonce', $nonce);
				}
			}
		}

		if (isset($this->config['force']) && $this->config['force'] === true) {
			$parameters['auth_type'] = 'reauthenticate';
			$parameters['auth_nonce'] = md5(uniqid(mt_rand(), true));

			SocialIntegration_Auth::storage()->set('fb_auth_nonce', $parameters['auth_nonce']);
		}

		// get the login url
		//$url = $this->api->getLoginUrl($parameters);
		$helper = $this->api->getRedirectLoginHelper();
		if (strpos('?', $this->endpoint) != -1)
		{
			$tmp = explode('?', $this->endpoint);
			$this->endpoint = $tmp[0].'/';
		}
		$url = $helper->getLoginUrl($this->endpoint, [$this->scope]);
		// redirect to facebook
		SocialIntegration_Auth::redirect($url);
	}

	/**
	 * {@inheritdoc}
	 */
	function loginFinish() {
		// in case we get error_reason=user_denied&error=access_denied
		if (isset($_REQUEST['error']) && $_REQUEST['error'] == "access_denied") {
			throw new Exception("Authentication failed! The user denied your request.", 5);
		}

		// in case we are using iOS/Facebook reverse authentication
		/*if (isset($_REQUEST['code'])) {
			$this->token("access_token", $_REQUEST['code']);
			$this->api->setAccessToken($this->token("access_token"));
			$this->api->setExtendedAccessToken();
			$access_token = $this->api->getAccessToken();			

			if ($access_token) {
				$this->token("access_token", $access_token);
				$this->api->setAccessToken($access_token);
			}

			$this->api->setAccessToken($this->token("access_token"));
		}*/


		// if auth_type is used, then an auth_nonce is passed back, and we need to check it.
		/*if (isset($_REQUEST['auth_nonce'])) {

			$nonce = SocialIntegration_Auth::storage()->get('fb_auth_nonce');

			//Delete the nonce
			SocialIntegration_Auth::storage()->delete('fb_auth_nonce');

			if ($_REQUEST['auth_nonce'] != $nonce) {
				throw new Exception("Authentication failed! Invalid nonce used for reauthentication.", 5);
			}
		}*/
		$helper = $this->api->getRedirectLoginHelper();
		if (isset($_GET['state'])) {
			$helper->getPersistentDataHandler()->set('state', $_GET['state']);
		}
		try {			
			$accessToken = $helper->getAccessToken();			
		} catch(Facebook\Exceptions\FacebookResponseException $e) {
			var_dump($e->getMessage());die();
			// When Graph returns an error
			throw new Exception('Graph returned an error: ' . $e->getMessage(), 5);
		} catch(Facebook\Exceptions\FacebookSDKException $e) {
			var_dump($e->getMessage());die();
			// When validation fails or other local issues
			throw new Exception('Facebook SDK returned an error: ' . $e->getMessage(), 5);
		}
		
		// try to get the UID of the connected user from fb, should be > 0
		if (! isset($accessToken)) {
			throw new Exception("Authentication failed! {$this->providerId} returned an invalid user id.", 5);
		}

		// set user as logged in
		$this->setUserConnected();

		// store facebook access token
		$this->token("access_token", $accessToken->getValue());
	}

	/**
	 * {@inheritdoc}
	 */
	function logout() {
		//$this->api->destroySession();
		parent::logout();
	}

	/**
	 * {@inheritdoc}
	 */
	function getUserProfile() {
		// request user profile from fb api
		try {
            $fields = array(
                'id', 'name', 'first_name', 'last_name', 'link', 'website',
                'gender', 'locale', 'about', 'email', 'hometown', 'location',
            				'birthday','picture.type(large)'
            );

			$data = $this->api->get('/me?fields=' . implode(',', $fields));
		} catch(Facebook\Exceptions\FacebookResponseException $e) {
			throw new Exception("User profile request failed! {$this->providerId} returned an error: $e", 6);
		}
		
		$data = $data->getDecodedBody();
		// if the provider identifier is not received, we assume the auth has failed
		if (!isset($data["id"])) {
			throw new Exception("User profile request failed! {$this->providerId} api returned an invalid response.", 6);
		}

		# store the user profile.
                $user_profile = array();
		$user_profile['identifier'] = (array_key_exists('id', $data)) ? $data['id'] : "";
		$user_profile['username'] = (array_key_exists('username', $data)) ? $data['username'] : "";
		$user_profile['displayName'] = (array_key_exists('name', $data)) ? $data['name'] : "";
		$user_profile['firstName'] = (array_key_exists('first_name', $data)) ? $data['first_name'] : "";
		$user_profile['lastName'] = (array_key_exists('last_name', $data)) ? $data['last_name'] : "";
		$user_profile['photoURL'] = isset($data['picture']['data']['url']) ? $data['picture']['data']['url'] : '';
		$user_profile['coverInfoURL'] = "https://graph.facebook.com/" . $user_profile['identifier'] . "?fields=cover&access_token=" . $this->token("access_token");
		$user_profile['profileURL'] = (array_key_exists('link', $data)) ? $data['link'] : "";
		$user_profile['webSiteURL'] = (array_key_exists('website', $data)) ? $data['website'] : "";
		$user_profile['gender'] = (array_key_exists('gender', $data)) ? $data['gender'] : "";
		$user_profile['language'] = (array_key_exists('locale', $data)) ? $data['locale'] : "";
		$user_profile['description'] = (array_key_exists('about', $data)) ? $data['about'] : "";
		$user_profile['email'] = (array_key_exists('email', $data)) ? $data['email'] : "";
		$user_profile['emailVerified'] = (array_key_exists('email', $data)) ? $data['email'] : "";
		$user_profile['region'] = (array_key_exists("location", $data) && array_key_exists("name", $data['location'])) ? $data['location']["name"] : "";
                $user_profile['access_token'] = $this->token("access_token");
		if (!empty($user_profile['region'])) {
			$regionArr = explode(',', $user_profile['region']);
			if (count($regionArr) > 1) {
				$user_profile['city']  = trim($regionArr[0]);
				$user_profile['country'] = trim($regionArr[1]);
			}
		}

		if (array_key_exists('birthday', $data)) {
			list($birthday_month, $birthday_day, $birthday_year) = explode("/", $data['birthday']);

			$user_profile['birthDay'] = (int) $birthday_day;
			$user_profile['birthMonth'] = (int) $birthday_month;
			$user_profile['birthYear'] = (int) $birthday_year;
		}
                $user = json_decode(json_encode($user_profile), true);
		return $user;
	}

	/**
	 * Attempt to retrieve the url to the cover image given the coverInfoURL
	 *
	 * @param  string $coverInfoURL coverInfoURL variable
	 * @return string               url to the cover image OR blank string
	 */
	function getCoverURL($coverInfoURL) {
		try {
			$headers = get_headers($coverInfoURL);
			if (substr($headers[0], 9, 3) != "404") {
				$coverOBJ = json_decode(file_get_contents($coverInfoURL));
				if (array_key_exists('cover', $coverOBJ)) {
					return $coverOBJ->cover->source;
				}
			}
		} catch (Exception $e) {

		}

		return "";
	}

	/**
	 * {@inheritdoc}
	 */
	function getUserContacts() {
		/*$apiCall = '?fields=link,name';
		$returnedContacts = array();
		$pagedList = false;

		do {
			try {
				$response = $this->api->get('/me/friends' . $apiCall);
			} catch (FacebookApiException $e) {
				throw new Exception('User contacts request failed! {$this->providerId} returned an error: $e');
			}

			// Prepare the next call if paging links have been returned
			if (array_key_exists('paging', $response) && array_key_exists('next', $response['paging'])) {
				$pagedList = true;
				$next_page = explode('friends', $response['paging']['next']);
				$apiCall = $next_page[1];
			} else {
				$pagedList = false;
			}

			// Add the new page contacts
			$returnedContacts = array_merge($returnedContacts, $response['data']);
		} while ($pagedList == true);

		$contacts = array();

		foreach ($returnedContacts as $item) {

			$uc = new Hybrid_User_Contact();
			$uc->identifier = (array_key_exists("id", $item)) ? $item["id"] : "";
			$uc->displayName = (array_key_exists("name", $item)) ? $item["name"] : "";
			$uc->profileURL = (array_key_exists("link", $item)) ? $item["link"] : "https://www.facebook.com/profile.php?id=" . $uc->identifier;
			$uc->photoURL = "https://graph.facebook.com/" . $uc->identifier . "/picture?width=150&height=150";

			$contacts[] = $uc;
		}*/

		return array();
	}

	/**
	 * Update user status
	 *
	 * @param mixed  $status An array describing the status, or string
	 * @param string $pageid (optional) User page id
	 * @return array
	 * @throw Exception
	 */
	function setUserStatus($status, $pageid = null) {
		if (!is_array($status)) {
			$status = array('message' => $status);
		}

            /*	if (is_null($pageid)) {
                    $pageid = 'me';

			// if post on page, get access_token page
		} else {
                        /*
			$access_token = null;
			foreach ($this->getUserPages(true) as $p) {
				if (isset($p['id']) && intval($p['id']) == intval($pageid)) {
					$access_token = $p['access_token'];
					break;
				}
			}

			if (is_null($access_token)) {
				throw new Exception("Update user page failed, page not found or not writable!");
			}

			$status['access_token'] = $access_token; 
		}*/

		try {
                    $response = $this->api->post('/me/feed', $status);
		} catch (Facebook\Exceptions\FacebookResponseException $e) {
                    throw new Exception("Update user status failed! {$this->providerId} returned an error: $e");
		}

		return null;
	}

	/**
	 * {@inheridoc}
	 */
	function getUserStatus($postid) {
		/*try {
			$postinfo = $this->api->api("/" . $postid);
		} catch (FacebookApiException $e) {
			throw new Exception("Cannot retrieve user status! {$this->providerId} returned an error: $e");
		}*/

		return null;
	}

	/**
	 * {@inheridoc}
	 */
	function getUserPages($writableonly = false) {
		/*if (( isset($this->config['scope']) && strpos($this->config['scope'], 'manage_pages') === false ) || (!isset($this->config['scope']) && strpos($this->scope, 'manage_pages') === false ))
			throw new Exception("User status requires manage_page permission!");

		try {
			$pages = $this->api->api("/me/accounts", 'get');
		} catch (FacebookApiException $e) {
			throw new Exception("Cannot retrieve user pages! {$this->providerId} returned an error: $e");
		}

		if (!isset($pages['data'])) {
			return array();
		}

		if (!$writableonly) {
			return $pages['data'];
		}

		$wrpages = array();
		foreach ($pages['data'] as $p) {
			if (isset($p['perms']) && in_array('CREATE_CONTENT', $p['perms'])) {
				$wrpages[] = $p;
			}
		}*/

		return null;
	}

	/**
	 * load the user latest activity
	 *    - timeline : all the stream
	 *    - me       : the user activity only
	 * {@inheritdoc}
	 */
	function getUserActivity($stream) {
		/*try {
			if ($stream == "me") {
				$response = $this->api->api('/me/feed');
			} else {
				$response = $this->api->api('/me/home');
			}
		} catch (FacebookApiException $e) {
			throw new Exception("User activity stream request failed! {$this->providerId} returned an error: $e");
		}

		if (!$response || !count($response['data'])) {
			return array();
		}

		$activities = array();

		foreach ($response['data'] as $item) {
			if ($stream == "me" && $item["from"]["id"] != $this->api->getUser()) {
				continue;
			}

			$ua = new Hybrid_User_Activity();

			$ua->id = (array_key_exists("id", $item)) ? $item["id"] : "";
			$ua->date = (array_key_exists("created_time", $item)) ? strtotime($item["created_time"]) : "";

			if ($item["type"] == "video") {
				$ua->text = (array_key_exists("link", $item)) ? $item["link"] : "";
			}

			if ($item["type"] == "link") {
				$ua->text = (array_key_exists("link", $item)) ? $item["link"] : "";
			}

			if (empty($ua->text) && isset($item["story"])) {
				$ua->text = (array_key_exists("link", $item)) ? $item["link"] : "";
			}

			if (empty($ua->text) && isset($item["message"])) {
				$ua->text = (array_key_exists("message", $item)) ? $item["message"] : "";
			}

			if (!empty($ua->text)) {
				$ua->user->identifier = (array_key_exists("id", $item["from"])) ? $item["from"]["id"] : "";
				$ua->user->displayName = (array_key_exists("name", $item["from"])) ? $item["from"]["name"] : "";
				$ua->user->profileURL = "https://www.facebook.com/profile.php?id=" . $ua->user->identifier;
				$ua->user->photoURL = "https://graph.facebook.com/" . $ua->user->identifier . "/picture?type=square";

				$activities[] = $ua;
			}
		}*/

		return array();
	}

}