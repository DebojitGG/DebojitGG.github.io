<?php

class SocialIntegration_Storage {
    
    public $components = array('Cookie', 'Session');

    /**
     * Constructor
     */
    function __construct() {
        $this->config("php_session_id", CakeSession::id());
    }

    /**
     * Config
     * @param String $key
     * @param String $value
     */
    public function config($key, $value = null) {
        $key = strtolower($key);

        if ($value) {
            CakeSession::write("HA_CONFIG_" . $key, serialize($value));
        } elseif (CakeSession::read("HA_CONFIG_" . $key)) {
            return unserialize(CakeSession::read("HA_CONFIG_" . $key));
        }
      
        return NULL;
    }

    /**
     * Get a key
     * @param String $key
     */
    public function get($key) {
        $key = strtolower($key);
        
        if (CakeSession::read('HA_STORE_' .$key )) {
            return unserialize(CakeSession::read('HA_STORE_' .$key ));
        }

        return NULL;
    }

    /**
     * GEt a set of key and value
     * @param String $key
     * @param String $value
     */
    public function set($key, $value) {
        $key = strtolower($key);
        CakeSession::write('HA_STORE_' .$key , serialize($value));
        
    }

    /**
     * Clear session storage
     */
    function clear() {
        CakeSession::write('HA_STORE' , ARRAY());
    }

    /**
     * Delete a specific key
     * @param String $key
     */
    function delete($key) {
        $key = strtolower($key);

        if (CakeSession::read('HA_STORE_' .$key )) {
            CakeSession::delete('HA_STORE_' .$key);
            $f = CakeSession::read('HA_STORE');
            unset($f[$key]);
            CakeSession::write('HA_STORE' , $f);
        }
    }

    /**
     * Delete a set
     * @param String $key
     */
    function deleteMatch($key) {
        $key = strtolower($key);
        
        if (CakeSession::read('HA_STORE_' .$key .'is_logged_in')) {          
            CakeSession::delete('HA_STORE_' .$key .'is_logged_in');
        }  
        
        if (CakeSession::read('HA_STORE')) {        
            $f = CakeSession::read('HA_STORE');
            foreach ($f as $k => $v) {
                if (strstr($k, $key)) {
                    unset($f[$k]);
                }
            }
            CakeSession::write('HA_STORE' , $f);
        }
    }

    /**
     * Get the storage session data into an array
     * @return Array
     */
    function getSessionData() {
        if (CakeSession::read('HA_STORE')) {
            return serialize(CakeSession::read('HA_STORE'));
        }

        return NULL;
    }

    /**
     * Restore the storage back into session from an array
     * @param Array $sessiondata
     */
    function restoreSessionData($sessiondata = NULL) {
        CakeSession::write('HA_STORE' , unserialize($sessiondata));
    }

}
