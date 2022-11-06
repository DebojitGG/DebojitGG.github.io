<?php

App::import('Lib/SocialIntegration', 'SocialIntergration');

class SocialIntegration_Providers_Facebook extends SocialIntergration {

    // default permissions, and a lot of them. You can change them from the configuration by setting the scope to what you want/need
    public $scope = "public_profile, email, user_friends";
    public $sdk_version = '3.2.3';

    /**
     * IDp wrappers initializer 
     */
    function initialize() {
        if (isset($_SESSION['facebook_sdk_version']) && $_SESSION['facebook_sdk_version']) {
            $this->sdk_version = $_SESSION['facebook_sdk_version'];
        }

        if (!$this->config["keys"]["id"] || !$this->config["keys"]["secret"]) {
            throw new Exception("Your application id and secret are required in order to connect to {$this->providerId}.", 4);
        }

        if (!class_exists('FacebookApiException', false)) {
            require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook/base_facebook.php";
            require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook/facebook.php";
        }

        if (isset(SocialIntegration_Auth::$config["proxy"])) {
            BaseFacebook::$CURL_OPTS[CURLOPT_PROXY] = SocialIntegration_Auth::$config["proxy"];
        }

        $trustForwarded = isset($this->config['trustForwarded']) ? (bool) $this->config['trustForwarded'] : false;
        $this->api = new Facebook(ARRAY('appId' => $this->config["keys"]["id"], 'secret' => $this->config["keys"]["secret"], 'trustForwarded' => $trustForwarded));

        if ($this->token("access_token")) {
            $this->api->setAccessToken($this->token("access_token"));
            $this->api->setExtendedAccessToken();
            $access_token = $this->api->getAccessToken();

            if ($access_token) {
                $this->token("access_token", $access_token);
                $this->api->setAccessToken($access_token);
            }

            $this->api->setAccessToken($this->token("access_token"));
        }

        $this->api->getUser();
    }

    /**
     * begin login step
     * 
     * simply call Facebook::require_login(). 
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
        $url = $this->api->getLoginUrl($parameters);

        // redirect to facebook
        SocialIntegration_Auth::redirect($url);
    }

    /**
     * finish login step 
     */
    function loginFinish() {
        // in case we get error_reason=user_denied&error=access_denied
        if (isset($_REQUEST['error']) && $_REQUEST['error'] == "access_denied") {
            throw new Exception("Authentication failed! The user denied your request.", 5);
        }

        // in case we are using iOS/Facebook reverse authentication
        if (isset($_REQUEST['access_token'])) {
            $this->token("access_token", $_REQUEST['access_token']);
            $this->api->setAccessToken($this->token("access_token"));
            $this->api->setExtendedAccessToken();
            $access_token = $this->api->getAccessToken();

            if ($access_token) {
                $this->token("access_token", $access_token);
                $this->api->setAccessToken($access_token);
            }

            $this->api->setAccessToken($this->token("access_token"));
        }


        // if auth_type is used, then an auth_nonce is passed back, and we need to check it.
        if (isset($_REQUEST['auth_nonce'])) {

            $nonce = SocialIntegration_Auth::storage()->get('fb_auth_nonce');

            //Delete the nonce
            SocialIntegration_Auth::storage()->delete('fb_auth_nonce');

            if ($_REQUEST['auth_nonce'] != $nonce) {
                throw new Exception("Authentication failed! Invalid nonce used for reauthentication.", 5);
            }
        }

        // try to get the UID of the connected user from fb, should be > 0 
        if (!$this->api->getUser()) {
            throw new Exception("Authentication failed! {$this->providerId} returned an invalid user id.", 5);
        }

        // set user as logged in
        $this->setUserConnected();

        // store facebook access token 
        $this->token("access_token", $this->api->getAccessToken());
    }

    /**
     * logout
     */
    function logout() {
        //session_destroy();
        $this->api->destroySession();

        parent::logout();
    }

    /**
     * load the user profile from the IDp api client
     */
    function getUserProfile() {
        $uc = array();
        // request user profile from fb api
        try {
            $data = $this->api->api('/me');
        } catch (FacebookApiException $e) {
            throw new Exception("User profile request failed! {$this->providerId} returned an error: $e", 6);
        }

        // if the provider identifier is not received, we assume the auth has failed
        if (!isset($data["id"])) {
            throw new Exception("User profile request failed! {$this->providerId} api returned an invalid response.", 6);
        }

        # store the user profile.
        $uc['identifier'] = (array_key_exists('id', $data)) ? $data['id'] : "";
        $uc['username'] = (array_key_exists('username', $data)) ? $data['username'] : "";
        $uc['displayName'] = (array_key_exists('name', $data)) ? $data['name'] : "";
        $uc['firstName'] = (array_key_exists('first_name', $data)) ? $data['first_name'] : "";
        $uc['lastName'] = (array_key_exists('last_name', $data)) ? $data['last_name'] : "";
        $uc['photoURL'] = "https://graph.facebook.com/" . $uc['identifier'] . "/picture?width=150&height=150";
        $uc['coverInfoURL'] = "https://graph.facebook.com/" . $uc['identifier'] . "?fields=cover&access_token=" . $this->api->getAccessToken();
        $uc['profileURL'] = (array_key_exists('link', $data)) ? $data['link'] : "";
        $uc['webSiteURL'] = (array_key_exists('website', $data)) ? $data['website'] : "";
        $uc['gender'] = (array_key_exists('gender', $data)) ? $data['gender'] : "";
        $uc['language'] = (array_key_exists('locale', $data)) ? $data['locale'] : "";
        $uc['description'] = (array_key_exists('about', $data)) ? $data['about'] : "";
        $uc['email'] = (array_key_exists('email', $data)) ? $data['email'] : "";
        $uc['emailVerified'] = (array_key_exists('email', $data)) ? $data['email'] : "";
        $uc['region'] = (array_key_exists("hometown", $data) && array_key_exists("name", $data['hometown'])) ? $data['hometown']["name"] : "";

        if (!empty($uc['region'])) {
            $regionArr = explode(',', $uc['region']);
            if (count($regionArr) > 1) {
                $uc['city'] = trim($regionArr[0]);
                $uc['country'] = trim($regionArr[1]);
            }
        }

        if (array_key_exists('birthday', $data)) {
            list($birthday_month, $birthday_day, $birthday_year) = explode("/", $data['birthday']);

            $uc['birthDay'] = (int) $birthday_day;
            $uc['birthMonth'] = (int) $birthday_month;
            $uc['birthYear'] = (int) $birthday_year;
        }
        $uc['access_token'] = $this->token("access_token");
        return $uc;
    }

    /**
     * Attempt to retrieve the url to the cover image given the coverInfoURL
     *
     * @param  string $coverInfoURL   coverInfoURL variable
     * @retval string                 url to the cover image OR blank string
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
     * load the user contacts
     */
    function getUserContacts() {
        $apiCall = '?fields=link,name';
        $returnedContacts = array();
        $pagedList = false;

        do {
            try {
                $response = $this->api->api('/me/friends' . $apiCall);
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

        $contacts = ARRAY();

        foreach ($returnedContacts as $item) {
            $uc = new Hybrid_User_Contact();

            $uc->identifier = (array_key_exists("id", $item)) ? $item["id"] : "";
            $uc->displayName = (array_key_exists("name", $item)) ? $item["name"] : "";
            $uc->profileURL = (array_key_exists("link", $item)) ? $item["link"] : "https://www.facebook.com/profile.php?id=" . $uc->identifier;
            $uc->photoURL = "https://graph.facebook.com/" . $uc->identifier . "/picture?width=150&height=150";

            $contacts[] = $uc;
        }

        return $contacts;
    }

    /**
     * update user status
     */
    function setUserStatus($status) {
        if (!is_array($status)) {
            $status = array('message' => $status);
        }

        if (is_null($pageid)) {
            $pageid = 'me';

            // if post on page, get access_token page
        } else {
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
        }

        try {
            $response = $this->api->api('/' . $pageid . '/feed', 'post', $status);
        } catch (FacebookApiException $e) {
            throw new Exception("Update user status failed! {$this->providerId} returned an error: $e");
        }

        return $response;
    }

    /**
     * load the user latest activity  
     *    - timeline : all the stream
     *    - me       : the user activity only  
     */
    function getUserActivity($stream) {
        try {
            if ($stream == "me") {
                $response = $this->api->api('/me/feed');
            } else {
                $response = $this->api->api('/me/home');
            }
        } catch (FacebookApiException $e) {
            throw new Exception("User activity stream request failed! {$this->providerId} returned an error: $e");
        }

        if (!$response || !count($response['data'])) {
            return ARRAY();
        }

        $activities = ARRAY();

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
        }

        return $activities;
    }

    // Get graph api call
    private function _getGraphResponse($method, $graph_api) {
        if ($this->token("access_token")) {
            $session = new FacebookSession($this->token("access_token"));

            try {
                if (!$session->validate()) {
                    $session = null;
                }
            } catch (Exception $e) {
                // catch any exceptions
                $session = null;
            }
        }

        if (!empty($session)) {
            $request = new FacebookRequest($session, $method, $graph_api);
            $response = $request->execute()
                    ->getGraphObject()
                    ->asArray();

            return $response;
        }

        return array();
    }

    function getUserInfo($uid) {
        try {
            $response = $this->_getGraphResponse('GET', '/' . $uid);
        } catch (FacebookApiException $e) {
            throw new Exception("User contacts request failed! {$this->providerId} returned an error: $e");
        }

        if (!$response || !count($response["data"])) {
            return ARRAY();
        }

        $contacts = ARRAY();

        foreach ($response["data"] as $key => $item) {
            $uc = array();

            $uc['identifier'] = !empty($item->id) ? $item->id : "";
            $uc['displayName'] = !empty($item->name) ? $item->name : "";
            $uc['profileURL'] = !empty($item->link) ? $item->link : "";
            $uc['photoURL'] = "https://graph.facebook.com/" . $item->id . "/picture?width=150&height=150";

            $contacts[] = $uc;
        }
        return $contacts;
    }

}