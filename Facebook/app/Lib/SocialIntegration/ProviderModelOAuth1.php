<?php
App::import('Lib/SocialIntegration', 'ProviderModel');
class SocialIntegration_Provider_Model_OAuth1 extends SocialIntegration_Provider_Model
{
	/**
	 * request_tokens as received from provider
	 * @var object
	 */
	public $request_tokens_raw = null;
	
	/**
	 * access_tokens as received from provider
	 * @var object
	 */
	public $access_tokens_raw  = null;
	
	/**
	* Try to get the error message from provider api
	* @param Numeric $code
	*/ 
	function errorMessageByStatus( $code = null ) { 
		$http_status_codes = ARRAY(
			200 => "OK: Success!",
			304 => "Not Modified: There was no new data to return.",
			400 => "Bad Request: The request was invalid.",
			401 => "Unauthorized.",
			403 => "Forbidden: The request is understood, but it has been refused.",
			404 => "Not Found: The URI requested is invalid or the resource requested does not exists.",
			406 => "Not Acceptable.", 
			500 => "Internal Server Error: Something is broken.",
			502 => "Bad Gateway.",
			503 => "Service Unavailable."
		);

		if( ! $code && $this->api ) 
			$code = $this->api->http_code;

		if( isset( $http_status_codes[ $code ] ) )
			return $code . " " . $http_status_codes[ $code ];
	}

	// --------------------------------------------------------------------

	/**
	* adapter initializer 
	*/
        function initialize()
	{
		// 1 - check application credentials
		if ( ! $this->config["keys"]["id"] || ! $this->config["keys"]["secret"] ){
			throw new Exception( "Your application key and secret are required in order to connect to {$this->providerId}.", 4 );
		}

		// 2 - include OAuth lib and client
		require_once SocialIntegration_Auth::$config["path_libraries"] . "OAuth/OAuth.php";
		require_once SocialIntegration_Auth::$config["path_libraries"] . "OAuth/OAuth1Client.php";

		// 3.1 - setup access_token if any stored
		if( $this->token( "access_token" ) ){
			$this->api = new OAuth1Client( 
				$this->config["keys"]["id"], $this->config["keys"]["secret"],
				$this->token( "access_token" ), $this->token( "access_token_secret" ) 
			);
		}

		// 3.2 - setup request_token if any stored, in order to exchange with an access token
		elseif( $this->token( "request_token" ) ){
			$this->api = new OAuth1Client( 
				$this->config["keys"]["id"], $this->config["keys"]["secret"], 
				$this->token( "request_token" ), $this->token( "request_token_secret" ) 
			);
		}

		// 3.3 - instanciate OAuth client with client credentials
		else{
			$this->api = new OAuth1Client( $this->config["keys"]["id"], $this->config["keys"]["secret"] );
		}

		// Set curl proxy if exist
		if( isset( SocialIntegration_Auth::$config["proxy"] ) ){
			$this->api->curl_proxy = SocialIntegration_Auth::$config["proxy"];
		}
	}

	// --------------------------------------------------------------------

	/**
	* begin login step 
	*/
	function loginBegin()
	{
		$tokens = $this->api->requestToken( $this->endpoint ); 

		// request tokens as received from provider
		$this->request_tokens_raw = $tokens;
		
		// check the last HTTP status code returned
		if ( $this->api->http_code != 200 ){
			throw new Exception( "Authentication failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus( $this->api->http_code ), 5 );
		}

		if ( ! isset( $tokens["oauth_token"] ) ){
			throw new Exception( "Authentication failed! {$this->providerId} returned an invalid oauth token.", 5 );
		}

		$this->token( "request_token"       , $tokens["oauth_token"] ); 
		$this->token( "request_token_secret", $tokens["oauth_token_secret"] ); 

		# redirect the user to the provider authentication url
		SocialIntegration_Auth::redirect( $this->api->authorizeUrl( $tokens ) );
	}

	// --------------------------------------------------------------------

	/**
	* finish login step 
	*/ 
	function loginFinish()
	{
		$oauth_token    = (array_key_exists('oauth_token',$_REQUEST))?$_REQUEST['oauth_token']:"";
		$oauth_verifier = (array_key_exists('oauth_verifier',$_REQUEST))?$_REQUEST['oauth_verifier']:"";

		if ( ! $oauth_token || ! $oauth_verifier ){
			throw new Exception( "Authentication failed! {$this->providerId} returned an invalid oauth verifier.", 5 );
		}

		// request an access token
		$tokens = $this->api->accessToken( $oauth_verifier );

		// access tokens as received from provider
		$this->access_tokens_raw = $tokens;

		// check the last HTTP status code returned
		if ( $this->api->http_code != 200 ){
			throw new Exception( "Authentication failed! {$this->providerId} returned an error. " . $this->errorMessageByStatus( $this->api->http_code ), 5 );
		}

		// we should have an access_token, or else, something has gone wrong
		if ( ! isset( $tokens["oauth_token"] ) ){
			throw new Exception( "Authentication failed! {$this->providerId} returned an invalid access token.", 5 );
		}

		// we no more need to store request tokens
		$this->deleteToken( "request_token"        );
		$this->deleteToken( "request_token_secret" );

		// store access_token for later user
		$this->token( "access_token"        , $tokens['oauth_token'] );
		$this->token( "access_token_secret" , $tokens['oauth_token_secret'] ); 

		// set user as logged in to the current provider
		$this->setUserConnected(); 
	}
}
