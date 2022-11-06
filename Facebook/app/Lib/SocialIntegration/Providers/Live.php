<?php

App::import('Lib/SocialIntegration', 'ProviderModelOAuth2');

class SocialIntegration_Providers_Live extends SocialIntegration_Provider_Model_OAuth2 {

	/**
	 * {@inheritdoc}
	 */
	public $scope = 'user.read people.read';

	/**
	 * {@inheritdoc}
	 */
	function initialize() {            
		parent::initialize();

		// Provider api end-points
		$this->api->api_base_url = 'https://graph.microsoft.com/v1.0/';
		$this->api->authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
		$this->api->token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

		$this->api->curl_authenticate_method = "POST";
	}
        
        function loginBegin() {
            $parameters = array("scope" => $this->scope, "tenant" => "common", "response_type" => "code", "response_mode"=>"query");
            $optionals = array("state");

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

        function loginFinish()
	{
		$error = (array_key_exists('error',$_REQUEST))?$_REQUEST['error']:"";

		// check for errors
		if ( $error ){ 
			throw new Exception( "Authentication failed! {$this->providerId} returned an error: $error", 5 );
		}

		// try to authenticate user
		$code = (array_key_exists('code',$_REQUEST))?$_REQUEST['code']:"";

		try{
			//var_dump($this->config["scope"]);die();
			$this->api->authenticate( $code , $this->scope); 
		}
		catch( Exception $e ){
			throw new Exception( "User profile request failed! {$this->providerId} returned an error: $e", 6 );
		}
		// check if authenticated
		if ( ! $this->api->access_token ){ 
			throw new Exception( "Authentication failed! {$this->providerId} returned an invalid access token.", 5 );
		}

		// store tokens
		$this->token( "access_token" , $this->api->access_token  );
		$this->token( "refresh_token", $this->api->refresh_token );
		$this->token( "expires_in"   , $this->api->access_token_expires_in );
		$this->token( "expires_at"   , $this->api->access_token_expires_at );

		// set user connected locally
		$this->setUserConnected();

	}
        
	/**
	 * {@inheritdoc}
	 */
	function getUserProfile() {
                    
		$data = $this->api->get("me", ['authorization_header' => true]);
		if (!isset($data->id)) {
			throw new Exception("User profile request failed! {$this->providerId} returned an invalid response.", 6);
		}

		$this->user->profile->identifier = (property_exists($data, 'id')) ? $data->id : "";
		$this->user->profile->firstName = (property_exists($data, 'first_name')) ? $data->first_name : "";
		$this->user->profile->lastName = (property_exists($data, 'last_name')) ? $data->last_name : "";
		$this->user->profile->displayName = (property_exists($data, 'name')) ? trim($data->name) : "";
		$this->user->profile->gender = (property_exists($data, 'gender')) ? $data->gender : "";

		//wl.basic
		$this->user->profile->profileURL = (property_exists($data, 'link')) ? $data->link : "";

		//wl.emails
		$this->user->profile->email = (property_exists($data, 'emails')) ? $data->emails->account : "";
		$this->user->profile->emailVerified = (property_exists($data, 'emails')) ? $data->emails->account : "";

		//wl.birthday
		$this->user->profile->birthDay = (property_exists($data, 'birth_day')) ? $data->birth_day : "";
		$this->user->profile->birthMonth = (property_exists($data, 'birth_month')) ? $data->birth_month : "";
		$this->user->profile->birthYear = (property_exists($data, 'birth_year')) ? $data->birth_year : "";

		return $this->user->profile;
	}

	/**
	 * Windows Live api does not support retrieval of email addresses (only hashes :/)
	 * {@inheritdoc}
	 */
	function getUserContacts() {
        $this->refreshToken();
		$response = $this->api->get('me/people/?$top=500', array('authorization_header'=>true));

		if ($this->api->http_code != 200) {
			throw new Exception('User contacts request failed! ' . $this->providerId . ' returned an error: ' . $this->errorMessageByStatus($this->api->http_code));
		}
	
                $response->data = $response->value;
		if (!isset($response->data) || ( isset($response->errcode) && $response->errcode != 0 )) {
			return array();
		}

		$contacts = array();
                
		foreach ($response->data as $item) {
			$uc = array();
			
			$uc['identifier'] = (property_exists($item, 'id')) ? $item->id : "";
			$uc['name'] = (property_exists($item, 'displayName')) ? $item->displayName : "";
			
			$emails = (property_exists($item, 'scoredEmailAddresses')) ? $item->scoredEmailAddresses : "";
			if(!empty($emails)){
				foreach($emails as $em){
					if(property_exists($em, 'address')){
						$uc['email'] = $em->address;
						break;
					}
				}		
			}			
			$uc['picture'] = '';
			if(!isset($uc['email'])){
				$uc['email'] = '';
			}
			if(empty($uc['name']) && !empty($uc['email'])){
				$uc['name'] = $uc['email'];
			}
			$contacts[] = $uc;
		}

		return $contacts;
	}

}