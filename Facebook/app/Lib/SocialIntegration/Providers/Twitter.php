<?php

App::import('Lib/SocialIntegration', 'ProviderModelOAuth1');

class SocialIntegration_Providers_Twitter extends SocialIntegration_Provider_Model_OAuth1 {

    /**
     * IDp wrappers initializer 
     */
    function initialize() {
        parent::initialize();

        // Provider api end-points 
        $this->api->api_base_url = "https://api.twitter.com/1.1/";
        $this->api->authorize_url = "https://api.twitter.com/oauth/authenticate";
        $this->api->request_token_url = "https://api.twitter.com/oauth/request_token";
        $this->api->access_token_url = "https://api.twitter.com/oauth/access_token";

        if (isset($this->config['api_version']) && $this->config['api_version']) {
            $this->api->api_base_url = "https://api.twitter.com/{$this->config['api_version']}/";
        }

        if (isset($this->config['authorize']) && $this->config['authorize']) {
            $this->api->authorize_url = "https://api.twitter.com/oauth/authorize";
        }

        $this->api->curl_auth_header = false;
    }

    /**
     * begin login step
     */
    function loginBegin() {
        // Initiate the Reverse Auth flow; cf. https://dev.twitter.com/docs/ios/using-reverse-auth
        if (isset($_REQUEST['reverse_auth']) && ($_REQUEST['reverse_auth'] == 'yes')) {
            $stage1 = $this->api->signedRequest($this->api->request_token_url, 'POST', array('x_auth_mode' => 'reverse_auth'));
           
            if ($this->api->http_code != 200) {
                throw new Exception("Authentication failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code), 5);
            }
            $responseObj = array('x_reverse_auth_parameters' => $stage1, 'x_reverse_auth_target' => $this->config["keys"]["key"]);
            $response = json_encode($responseObj);
            header("Content-Type: application/json", true, 200);
            echo $response;
            die();
        }

        $retries = 0;
        do {
            // only do a delay if it's a retry
            if ($retries > 0)
                usleep(500000);

            $tokens = $this->api->requestToken($this->config['redirect_uri']);

            if ($this->api->http_code != 200 || !isset($tokens["oauth_token"])) {
                $this->deleteToken('request_token');
                $this->deleteToken('access_token');
            }

            $retries++;
        } while (!isset($tokens["oauth_token"]) && $retries < 2);

        // request tokens as received from provider
        $this->request_tokens_raw = $tokens;

        // check the last HTTP status code returned
        if ($this->api->http_code != 200) {
            $this->deleteToken('request_token');
            $this->deleteToken('access_token');
            throw new Exception("Authentication failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code), 5);
        }

        if (!isset($tokens["oauth_token"])) {
            $this->deleteToken('request_token');
            $this->deleteToken('access_token');
            throw new Exception("Authentication failed! {$this->providerId} returned an invalid oauth token.", 5);
        }

        $this->token("request_token", $tokens["oauth_token"]);
        $this->token("request_token_secret", $tokens["oauth_token_secret"]);

        // redirect the user to the provider authentication url with force_login
        if (isset($this->config['force_login']) && $this->config['force_login']) {
            SocialIntegration_Auth::redirect($this->api->authorizeUrl($tokens, array('force_login' => true)));
        }

        // else, redirect the user to the provider authentication url
        SocialIntegration_Auth::redirect($this->api->authorizeUrl($tokens));
    }

    /**
     * finish login step 
     */
    function loginFinish() {
        // in case we are completing a Reverse Auth flow; cf. https://dev.twitter.com/docs/ios/using-reverse-auth
        if (isset($_REQUEST['oauth_token_secret'])) {
            $tokens = $_REQUEST;
            $this->access_tokens_raw = $tokens;

            // we should have an access_token unless something has gone wrong
            if (!isset($tokens["oauth_token"])) {
                throw new Exception("Authentication failed! {$this->providerId} returned an invalid access token.", 5);
            }

            // Get rid of tokens we don't need
            $this->deleteToken("request_token");
            $this->deleteToken("request_token_secret");

            // Store access_token and secret for later use
            $this->token("access_token", $tokens['oauth_token']);
            $this->token("access_token_secret", $tokens['oauth_token_secret']);

            // set user as logged in to the current provider
            $this->setUserConnected();
            return;
        }
        parent::loginFinish();
    }

    /**
     * load the user profile from the IDp api client
     */
    function getUserProfile() {
        $response = $this->api->get('account/verify_credentials.json?include_email=true');

        // check the last HTTP status code returned
        if ($this->api->http_code != 200) {
            throw new Exception("User profile request failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code), 6);
        }

        if (!is_object($response) || !isset($response->id)) {
            throw new Exception("User profile request failed! {$this->providerId} api returned an invalid response.", 6);
        }

        $profile = ARRAY();
        $profile['email'] = (property_exists($response, 'email')) ? $response->email : "";
        $profile['identifier'] = (property_exists($response, 'id')) ? $response->id : "";
        $profile['displayName'] = (property_exists($response, 'name')) ? $response->name : "";
        $profile['description'] = (property_exists($response, 'description')) ? $response->description : "";
        $profile['firstName'] = (property_exists($response, 'name')) ? $response->name : "";
        $profile['photoURL'] = (property_exists($response, 'profile_image_url')) ? $response->profile_image_url : "";
        $profile['profileURL'] = (property_exists($response, 'screen_name')) ? ("http://twitter.com/" . $response->screen_name) : "";
        $profile['webSiteURL'] = (property_exists($response, 'url')) ? $response->url : "";
        $profile['region'] = (property_exists($response, 'location')) ? $response->location : "";

        return $profile;
    }

    /**
     * load the user contacts
     */
    function getUserContacts() {
        $parameters = array('cursor' => '-1');
        $response = $this->api->get('followers/ids.json', $parameters);

        // check the last HTTP status code returned
        if ($this->api->http_code != 200) {
            throw new Exception("User contacts request failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code));
        }

        if (!$response || !count($response->ids)) {
            return ARRAY();
        }

        // 75 id per time should be okey
        $contactsids = array_chunk($response->ids, 75);

        $contacts = ARRAY();
        $key_temp = 0;
        foreach ($contactsids as $chunk) {
            $parameters = array('user_id' => implode(",", $chunk));
            $response = $this->api->get('users/lookup.json', $parameters);

            // check the last HTTP status code returned
            if ($this->api->http_code != 200) {
                throw new Exception("User contacts request failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code));
            }

            if ($response && count($response)) {
                foreach ($response as $item) {
                    // $uc = new SocialIntegration_User_Contact();
                    $contacts[$key_temp]['id'] = (property_exists($item, 'id')) ? $item->id : "";
                    $contacts[$key_temp]['name'] = (property_exists($item, 'name')) ? $item->name : "";
                    $contacts[$key_temp]['profileURL'] = (property_exists($item, 'screen_name')) ? ("http://twitter.com/" . $item->screen_name) : "";
                    $contacts[$key_temp]['picture'] = (property_exists($item, 'profile_image_url')) ? $item->profile_image_url : "";
                    $contacts[$key_temp]['description'] = (property_exists($item, 'description')) ? $item->description : "";
                    $key_temp++;
                    // $contacts[] = $uc;
                }
            }
        }

        return $contacts;
    }

    /**
     * update user status
     */
    function setUserStatus($status) {
        $parameters = array('status' => $status);
        $response = $this->api->post('statuses/update.json', $parameters);

        // check the last HTTP status code returned
        if ($this->api->http_code != 200) {
            throw new Exception("Update user status failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code));
        }
    }

    /**
     * load the user latest activity  
     *    - timeline : all the stream
     *    - me       : the user activity only  
     *
     * by default return the timeline
     */
    function getUserActivity($stream) {
        if ($stream == "me") {
            $response = $this->api->get('statuses/user_timeline.json');
        } else {
            $response = $this->api->get('statuses/home_timeline.json');
        }

        // check the last HTTP status code returned
        if ($this->api->http_code != 200) {
            throw new Exception("User activity stream request failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus($this->api->http_code));
        }

        if (!$response) {
            return ARRAY();
        }

        $activities = ARRAY();
        $key_temp = 0;
        foreach ($response as $item) {
            //$ua = new SocialIntegration_User_Activity();

            $activities[$key_temp]['id'] = (property_exists($item, 'id')) ? $item->id : "";
            $activities[$key_temp]['date'] = (property_exists($item, 'created_at')) ? strtotime($item->created_at) : "";
            $activities[$key_temp]['text'] = (property_exists($item, 'text')) ? $item->text : "";

            $activities[$key_temp]['identifier'] = (property_exists($item->user, 'id')) ? $item->user->id : "";
            $activities[$key_temp]['displayName'] = (property_exists($item->user, 'name')) ? $item->user->name : "";
            $activities[$key_temp]['profileURL'] = (property_exists($item->user, 'screen_name')) ? ("http://twitter.com/" . $item->user->screen_name) : "";
            $activities[$key_temp]['photoURL'] = (property_exists($item->user, 'profile_image_url')) ? $item->user->profile_image_url : "";
            $key_temp++;
            // $activities[] = $ua;
        }

        return $activities;
    }

    function sendInvite($friendsToJoin, $user_data = null) {
        if (isset($user_data['subject']) && !empty($user_data['subject'])) {
            $subject = $user_data['subject'];
        } else {
            $subject = 'You have received an invitation to join our social network.';
        }

        if (isset($user_data['body']) && !empty($user_data['body'])) {
            $body = $user_data['body'];
        } else {
            $body = 'You have received an invitation to join our social network.';
        }
        foreach ($friendsToJoin as $recipient => $recipient_name) {
            if (!empty($recipient)){
                $response_linkedin = $this->api->post(
                    'direct_messages/new.json',
                    array('text' => $body, 'user_id' => $recipient, 'wrap_links' => true)       

               );
            }
            
        }
    }

}
