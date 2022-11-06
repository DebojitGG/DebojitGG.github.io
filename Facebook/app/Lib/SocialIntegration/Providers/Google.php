<?php

App::import('Lib/SocialIntegration', 'ProviderModelOAuth2');

class SocialIntegration_Providers_Google extends SocialIntegration_Provider_Model_OAuth2 {

    // > more infos on google APIs: http://developer.google.com (official site)
    // or here: http://discovery-check.appspot.com/ (unofficial but up to date)
    // default permissions 
    public $scope = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/contacts.other.readonly";

    /**
     * IDp wrappers initializer 
     */
    function initialize() {
        parent::initialize();

        // Provider api end-points
        $this->api->authorize_url = "https://accounts.google.com/o/oauth2/auth";
        $this->api->token_url = "https://accounts.google.com/o/oauth2/token";
        $this->api->token_info_url = "https://www.googleapis.com/oauth2/v2/tokeninfo";
        $this->api->revoke_token_url = "https://accounts.google.com/o/oauth2/revoke";

        // Override the redirect uri when it's set in the config parameters. This way we prevent
        // redirect uri mismatches when authenticating with Google.
        if (isset($this->config['redirect_uri']) && !empty($this->config['redirect_uri'])) {
            $this->api->redirect_uri = $this->config['redirect_uri'];
        }
    }

    /**
     * begin login step 
     */
    function loginBegin() {
        $parameters = array("scope" => $this->scope, "access_type" => "offline");
        $optionals = array("scope", "access_type", "redirect_uri", "approval_prompt", "hd", "state");

        foreach ($optionals as $parameter) {
            if (isset($this->config[$parameter]) && !empty($this->config[$parameter])) {
                $parameters[$parameter] = $this->config[$parameter];
            }
            if (isset($this->config["scope"]) && !empty($this->config["scope"])) {
                $this->scope = $this->config["scope"];
            }
        }

        SocialIntegration_Auth::redirect($this->api->authorizeUrl($parameters));
    }

    /**
     * load the user profile from the IDp api client
     */
    function getUserProfile() {
        // refresh tokens if needed
        $this->refreshToken();

        // ask google api for user infos
        if (strpos($this->scope, '/auth/userinfo.email') !== false) {
            $verified = $this->api->api("https://www.googleapis.com/oauth2/v2/userinfo");

            if (!isset($verified->id) || isset($verified->error))
                $verified = new stdClass();
        } else {
            $verified = $this->api->api("https://www.googleapis.com/plus/v1/people/me/openIdConnect");

            if (!isset($verified->sub) || isset($verified->error))
                $verified = new stdClass();
        }

        $response = $this->api->api("https://openidconnect.googleapis.com/v1/userinfo");
        if (!isset($response->sub) || isset($response->error)) {
        	throw new Exception("User profile request failed! {$this->providerId} returned an invalid response.", 6);
        }
        
        $uc = array();
        # store the user profile.
        $uc['identifier'] = (property_exists($verified, 'id')) ? $verified->id : ((property_exists($response, 'sub')) ? $response->sub : "");
        $uc['displayName'] = (property_exists($response, 'name')) ? $response->name : "";
        $uc['first_name'] = (property_exists($response, 'givenName')) ? $response->givenName : "";
        $uc['last_name'] = (property_exists($response, 'familyName')) ? $response->familyName : "";
        $uc['profileURL'] = (property_exists($response, 'profile')) ? $response->profile : "";
        $uc['photoURL'] = (property_exists($response, 'picture')) ? $response->picture : '';
        $uc['gender'] = (property_exists($response, 'gender')) ? $response->gender : "";
        $uc['description'] = (property_exists($response, 'aboutMe')) ? $response->aboutMe : "";
        $uc['email'] = (property_exists($response, 'email')) ? $response->email : ((property_exists($verified, 'email')) ? $verified->email : "");
        $uc['access_token'] = $this->api->access_token;
        return $uc;
    }

    /**
     * load the user (Gmail and google plus) contacts 
     *  ..toComplete
     */
    function getUserContacts() {
        // refresh tokens if needed 
        $this->refreshToken();

        $key_temp = 0;
        if (!isset($this->config['contacts_param'])) {
            $this->config['contacts_param'] = array("pageSize" => 1000, "readMask" => 'emailAddresses,names');
        }

        $response = $this->api->api("https://people.googleapis.com/v1/otherContacts?"
                . http_build_query($this->config['contacts_param']));


        if (!$response->otherContacts) {
            return ARRAY();
        }
        $contacts = array();
        foreach ($response->otherContacts as $key_temp => $entry) {
            if (isset($entry->emailAddresses)  && !empty($entry->emailAddresses)) {
                $contacts[$key_temp]['email'] = $entry->emailAddresses[0]->value;
                if (isset($entry->names)  && !empty($entry->names)) {
                    $contacts[$key_temp]['name'] = $entry->names[0]->displayName;
                } else {
                    $contacts[$key_temp]['name'] = $contacts[$key_temp]['email'];
                }
            }
        }

        return $contacts;
    }
    
    public function logout() {
        $this->api->revokeToken($this->api->access_token);
        parent::logout();
    }

    /**
     * Add to the $url new parameters
     * @param string $url
     * @param array $params
     * @return string
     */
    function addUrlParam($url, array $params) {
        $query = parse_url($url, PHP_URL_QUERY);

        // Returns the URL string with new parameters
        if ($query) {
            $url .= '&' . http_build_query($params);
        } else {
            $url .= '?' . http_build_query($params);
        }
        return $url;
    }

}
