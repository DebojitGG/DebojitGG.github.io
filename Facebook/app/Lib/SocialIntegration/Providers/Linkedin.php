<?phpApp::import('Lib/SocialIntegration', 'ProviderModelOAuth2');class SocialIntegration_Providers_LinkedIn extends SocialIntegration_Provider_Model_OAuth2 {	/**        * {@inheritdoc}        */        public $scope = 'r_liteprofile r_emailaddress';                public $state = 'DCEeFWf45A53sdfKef421';	function initialize()         {            parent::initialize();                           // Provider api end-points            $this->api->api_base_url = "https://api.linkedin.com/v2/";            $this->api->authorize_url = "https://www.linkedin.com/uas/oauth2/authorization";            $this->api->token_url = "https://www.linkedin.com/uas/oauth2/accessToken";            $this->api->state = $this->state;            $this->api->sign_token_name = 'oauth2_access_token';        }        /**         * begin login step          */        function loginBegin() {                           SocialIntegration_Auth::redirect( $this->api->authorizeUrl(array("response_type" => "code", "scope" => $this->scope, "state" => $this->state)));         }	/**	 * {@inheritdoc}	 */	function getUserProfile() {                // refresh tokens if needed                $this->refreshToken();            		try {                    $response = $this->api->api('me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))');		} catch (LinkedInException $e) {                    throw new Exception("User profile request failed! {$this->providerId} returned an error: $e", 6);		}                $profile = array();              		if (isset($response->firstName) && !empty($response->firstName)) {			$data = $response;			$profile['identifier'] = (string) $data->{'id'};            $firstNamePreferedLocale = $data->{'firstName'}->{'preferredLocale'}->{'language'} . '_' . $data->{'firstName'}->{'preferredLocale'}->{'country'};            $profile['first_name'] = (string) $data->{'firstName'}->{'localized'}->$firstNamePreferedLocale;            $lastNamePreferedLocale = $data->{'lastName'}->{'preferredLocale'}->{'language'} . '_' . $data->{'lastName'}->{'preferredLocale'}->{'country'};			$profile['last_name'] = (string) $data->{'lastName'}->{'localized'}->$lastNamePreferedLocale;			$profile['displayName'] = trim($profile['first_name'] . " " . $profile['last_name']);			                        if (isset($data->profilePicture->{'displayImage~'})){                            $picsElment = $data->profilePicture->{'displayImage~'}->elements;                            if (!empty($picsElment)) {                                $profile['photoURL'] = isset($picsElment[3])? $picsElment[3]->identifiers[0]->identifier :  $picsElment[0]->identifiers[0]->identifier;                            }                        }                        if(!isset($profile['photoURL'])) {                            $profile['photoURL'] = (string) $profile['photoURL'];                            $profile['profileURL'] = (string) $profile['photoURL'];                        }                        if(isset($data->{'summary'})){                            $profile['description'] = (string) $data->{'summary'};                        }                        $profile['access_token'] = $this->token( "access_token" );					} else {			throw new Exception("User profile request failed! {$this->providerId} returned an invalid response.", 6);		}                try {                        $response = $this->api->api('emailAddress?q=members&projection=(elements*(handle~))');                        if (isset($response->elements) && !empty($response->elements)) {                                                  $profile['email'] = (string) $response->elements[0]->{'handle~'}->emailAddress;                            $profile['emailVerified'] = (string) $response->elements[0]->{'handle~'}->emailAddress;                        }                        		} catch (LinkedInException $e) {                        return $profile;		}                               return $profile;	}	/**	 * {@inheritdoc}	 */	function getUserContacts() {		try {			$response = $this->api->profile('~/connections:(id,first-name,last-name,picture-url,public-profile-url,summary)');		} catch (LinkedInException $e) {			throw new Exception("User contacts request failed! {$this->providerId} returned an error: $e");		}		if (!$response || !$response['success']) {			return array();		}		$connections = new SimpleXMLElement($response['linkedin']);		$contacts = array();		foreach ($connections->person as $connection) {			$uc = new Hybrid_User_Contact();			$uc->identifier = (string) $connection->id;			$uc->displayName = (string) $connection->{'last-name'} . " " . $connection->{'first-name'};			$uc->profileURL = (string) $connection->{'public-profile-url'};			$uc->photoURL = (string) $connection->{'picture-url'};			$uc->description = (string) $connection->{'summary'};			$contacts[] = $uc;		}		return $contacts;	}	/**	 * {@inheritdoc}	 */	function setUserStatus($status) {		$parameters = array();		$private = true; // share with your connections only		if (is_array($status)) {			if (isset($status[0]) && !empty($status[0]))				$parameters["title"] = $status[0]; // post title			if (isset($status[1]) && !empty($status[1]))				$parameters["comment"] = $status[1]; // post comment			if (isset($status[2]) && !empty($status[2]))				$parameters["submitted-url"] = $status[2]; // post url			if (isset($status[3]) && !empty($status[3]))				$parameters["submitted-image-url"] = $status[3]; // post picture url			if (isset($status[4]) && !empty($status[4]))				$private = $status[4]; // true or false		}		else {			$parameters["comment"] = $status;		}		try {			$response = $this->api->share('new', $parameters, $private);		} catch (LinkedInException $e) {			throw new Exception("Update user status update failed!  {$this->providerId} returned an error: $e");		}		if (!$response || !$response['success']) {			throw new Exception("Update user status update failed! {$this->providerId} returned an error.");		}		return $response;	}	/**	 * load the user latest activity	 *    - timeline : all the stream	 *    - me       : the user activity only	 * {@inheritdoc}	 */	function getUserActivity($stream) {		try {			if ($stream == "me") {				$response = $this->api->updates('?type=SHAR&scope=self&count=25');			} else {				$response = $this->api->updates('?type=SHAR&count=25');			}		} catch (LinkedInException $e) {			throw new Exception("User activity stream request failed! {$this->providerId} returned an error: $e");		}		if (!$response || !$response['success']) {			return array();		}		$updates = new SimpleXMLElement($response['linkedin']);		$activities = array();		foreach ($updates->update as $update) {			$person = $update->{'update-content'}->person;			$share = $update->{'update-content'}->person->{'current-share'};			$ua = array();			$ua['id'] = (string) $update->id;			$ua['date'] = (string) $update->timestamp;			$ua['text'] = (string) $share->{'comment'};			$ua['user']['identifier'] = (string) $person->id;			$ua['user']['displayName'] = (string) $person->{'first-name'} . ' ' . $person->{'last-name'};			$ua['user']['profileURL'] = (string) $person->{'site-standard-profile-request'}->url;			$ua['user']['photoURL'] = null;			$activities[] = $ua;		}		return $activities;	}}