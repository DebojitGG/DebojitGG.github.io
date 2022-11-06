<?php

App::import('Lib/SocialIntegration', 'SocialIntergration');

class SocialIntegration_Providers_Facebook extends SocialIntergration {

    // default permissions, and a lot of them. You can change them from the configuration by setting the scope to what you want/need
    public $scope = "public_profile, email, user_friends";
    public $sdk_version = '4.0.0';

    /**
     * IDp wrappers initializer
     */
    function initialize() {
        if (isset($_SESSION['facebook_sdk_version']) && $_SESSION['facebook_sdk_version']) {
            $this->sdk_version = $_SESSION['facebook_sdk_version'];
        }

        // version 4.0.0
        if (!$this->config["keys"]["id"] || !$this->config["keys"]["secret"]) {
            throw new Exception("Your application id and secret are required in order to connect to {$this->providerId}.", 4);
        }

        if (!class_exists('FacebookSDKException', false)) {
            require_once SocialIntegration_Auth::$config["path_libraries"] . "Facebook/autoload.php";
        }
        // Set session from api secret
        Facebook\FacebookSession::setDefaultApplication($this->config["keys"]["id"], $this->config["keys"]["secret"]);
        $this->api = new Facebook\FacebookRedirectLoginHelper($this->config["redirect_uri"], $this->config["keys"]["id"], $this->config["keys"]["secret"]);

    }

    /**
     * begin login step
     *
     * simply call Facebook::require_login().
     */
    function loginBegin() {
        if (isset($this->config["scope"]) && !empty($this->config["scope"])) {
            $this->scope = $this->config["scope"];
        }

        $params = array("scope" => $this->scope);
        $url = $this->api->getLoginUrl($params);
        // redirect to facebook
        SocialIntegration_Auth::redirect($url);
    }

    /**
     * finish login step
     */
    function loginFinish() {
        // version 4.0.0
        if ($this->token("access_token")) {
            $session = new Facebook\FacebookSession($this->token("access_token"));

            try {
                if (!$session->validate()) {
                    $session = null;
                }
            } catch (Exception $e) {
                // catch any exceptions
                $session = null;
            }
        }

        if (!isset($session) || $session === null) {
            // no session exists
            try {
                $session = $this->api->getSessionFromRedirect();
            } catch (Facebook\FacebookRequestException $ex) {
                // When Facebook returns an error
                // handle this better in production code
                throw $ex;
            } catch (Exception $ex) {
                // When validation fails or other local issues
                // handle this better in production code
                throw $ex;
            }
        }

        // Check if a session exists
        if (isset($session)) {
            // Save the token
            $this->token("access_token", $session->getToken());

            // Create session using saved token or the new one we generated at login
            $session = new Facebook\FacebookSession($session->getToken());
        } else {
            throw new Exception("Authentication failed! {$this->providerId} returned an invalid user id.", 5);
        }

        // set user as logged in
        $this->setUserConnected();

        // store facebook access token
        $this->token("access_token", $session->getToken());

    }

    /**
     * logout
     */
    function logout() {
        //session_destroy();

        parent::logout();
    }

    /**
     * load the user profile from the IDp api client
     */
    function getUserProfile() {
        $uc = array();
        // version 4.0.0
        try {
            $data = $this->_getGraphResponse('GET', '/me');
        } catch (FacebookApiException $e) {
            throw new Exception("User contacts request failed! {$this->providerId} returned an error: $e");
        }

        // if the provider identifier is not received, we assume the auth has failed
        if (!isset($data["id"])) {
            throw new Exception("User profile request failed! {$this->providerId} api returned an invalid response.", 6);
        }

        # store the user profile.
        $uc['identifier'] = (array_key_exists('id', $data)) ? $data['id'] : "";
        $uc['username'] = (array_key_exists('username', $data)) ? $data['username'] : "";
        $uc['displayName'] = (array_key_exists('name', $data)) ? $data['name'] : "";
        $uc['first_name'] = (array_key_exists('first_name', $data)) ? $data['first_name'] : "";
        $uc['last_name'] = (array_key_exists('last_name', $data)) ? $data['last_name'] : "";
        $uc['profileURL'] = "https://www.facebook.com/" . $data['id'];
        $uc['photoURL'] = "https://graph.facebook.com/" . $data['id'] . "/picture?width=150&height=150";
        $uc['gender'] = (array_key_exists('gender', $data)) ? $data['gender'] : "";
        $uc['description'] = (array_key_exists('bio', $data)) ? $data['bio'] : "";
        $uc['email'] = (array_key_exists('email', $data)) ? $data['email'] : "";

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
        // version 4.0.0
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
        // version 4.0.0
        try {
            $response = $this->_getGraphResponse('GET', '/me/friends');
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

    /**
     * update user status
     */
    function setUserStatus($status) {
        // version 4.0.0
        $parameters = array();

        if (is_array($status)) {
            $parameters = $status;
        } else {
            $parameters["message"] = $status;
        }

        try {
            $response = $this->api->api("/me/feed", "post", $parameters);
        } catch (FacebookApiException $e) {
            throw new Exception("Update user status failed! {$this->providerId} returned an error: $e");
        }

    }

    /**
     * load the user latest activity
     *    - timeline : all the stream
     *    - me       : the user activity only
     */
    function getUserActivity($stream) {
        // version 4.0.0
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

            $ua = new SocialIntegration_User_Activity();

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
                $ua->user->photoURL = "https://graph.facebook.com/" . $item["from"]["id"] . "/picture?type=square";

                $activities[] = $ua;
            }
        }

        return $activities;

    }

    // Get graph api call
    private function _getGraphResponse($method, $graph_api) {
        if ($this->token("access_token")) {
            $session = new Facebook\FacebookSession($this->token("access_token"));

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
            $request = new Facebook\FacebookRequest($session, $method, $graph_api);
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