<?php
/**
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2014, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
*/

/**
 * Errors manager
 * 
 * HybridAuth errors are stored in Hybrid::storage() and not displayed directly to the end user 
 */
class Hybrid_Error
{
	/**
	* Store error in session
	*
	* @param String $message
	* @param Number $code
	* @param String $trace
	* @param String $previous
	*/
	public static function setError( $message, $code = NULL, $trace = NULL, $previous = NULL )
	{
		Hybrid_Logger::info( "Enter Hybrid_Error::setError( $message )" );

		SocialIntegration_Auth::storage()->set( "hauth_session.error.status"  , 1         );
		SocialIntegration_Auth::storage()->set( "hauth_session.error.message" , $message  );
		SocialIntegration_Auth::storage()->set( "hauth_session.error.code"    , $code     );
		SocialIntegration_Auth::storage()->set( "hauth_session.error.trace"   , $trace    );
		SocialIntegration_Auth::storage()->set( "hauth_session.error.previous", $previous );
	}

	/**
	* Clear the last error
	*/
	public static function clearError()
	{ 
		Hybrid_Logger::info( "Enter Hybrid_Error::clearError()" );

		SocialIntegration_Auth::storage()->delete( "hauth_session.error.status"   );
		SocialIntegration_Auth::storage()->delete( "hauth_session.error.message"  );
		SocialIntegration_Auth::storage()->delete( "hauth_session.error.code"     );
		SocialIntegration_Auth::storage()->delete( "hauth_session.error.trace"    );
		SocialIntegration_Auth::storage()->delete( "hauth_session.error.previous" );
	}

	/**
	* Checks to see if there is a an error. 
	* 
	* @return boolean True if there is an error.
	*/
	public static function hasError()
	{ 
		return (bool) SocialIntegration_Auth::storage()->get( "hauth_session.error.status" );
	}

	/**
	* return error message 
	*/
	public static function getErrorMessage()
	{ 
		return SocialIntegration_Auth::storage()->get( "hauth_session.error.message" );
	}

	/**
	* return error code  
	*/
	public static function getErrorCode()
	{ 
		return SocialIntegration_Auth::storage()->get( "hauth_session.error.code" );
	}

	/**
	* return string detailed error backtrace as string.
	*/
	public static function getErrorTrace()
	{ 
		return SocialIntegration_Auth::storage()->get( "hauth_session.error.trace" );
	}

	/**
	* @return string detailed error backtrace as string.
	*/
	public static function getErrorPrevious()
	{ 
		return SocialIntegration_Auth::storage()->get( "hauth_session.error.previous" );
	}
}
