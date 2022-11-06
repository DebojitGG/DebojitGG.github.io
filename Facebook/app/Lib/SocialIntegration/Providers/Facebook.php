<?php
$default_sdk = '3.2.3';
if (isset($_SESSION['facebook_sdk_version']) && $_SESSION['facebook_sdk_version']) {
    $default_sdk = $_SESSION['facebook_sdk_version'];
}
if($default_sdk == '3.2.3')
    require_once SocialIntegration_Auth::$config["path_providers"] . "Facebook_3_2_3.php" ;
else
    require_once SocialIntegration_Auth::$config["path_providers"] . "Facebook_5_0_0.php" ;
