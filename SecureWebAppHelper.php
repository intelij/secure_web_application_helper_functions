<?php
/**
 * Created by PhpStorm.
 * User: khululekanim
 * Date: 11/08/15
 * Time: 08:56
 */

class SecureWebAppHelper {

    /**
     * usage
     * $get_params = allowedGetParams(['username', 'password']);
     */
    function allowedGetParams($allowed_params=[]) {
        $allowed_array = [];
        foreach($allowed_params as $param) {
            if(isset($_GET[$param])) {
                $allowed_array[$param] = $_GET[$param];
            } else {
                $allowed_array[$param] = NULL;
            }
        }
        return $allowed_array;
    }

    /**
     * usage
     * $post_params = allowedPostParams(['username', 'password']);
     */
    function allowedPostParams($allowed_params=[]) {
        $allowed_array = [];
        foreach($allowed_params as $param) {
            if(isset($_POST[$param])) {
                $allowed_array[$param] = $_POST[$param];
            } else {
                $allowed_array[$param] = NULL;
            }
        }
        return $allowed_array;
    }

    /** Sanitize for HTML output */
    function h($string) {
        return htmlspecialchars($string);
    }

    /** Sanitize for JavaScript output */
    function j($string) {
        return json_encode($string);
    }

    /** Sanitize for use in a URL */
    function u($string) {
        return urlencode($string);
    }

    /**
     * generate a token for use with CSRF protection
     */
    function generateCSRFToken() {
        return md5(uniqid(rand(), TRUE));
    }

    /**
     * destroy token
     */
    function destroyCSFRToken() {
        $_SESSION['csrf_token'] = null;
        $_SESSION['csrf_token_time'] = null;
        return true;
    }

    /**
     * for use in the form
     * Usage: echo CSFRTokenTag();
     */
    function CSFRTokenTag() {
        $token = $this->generateCSRFToken();
        return "<input type=\"hidden\" name=\"csrf_token\" value=\"".$token."\">";
    }

    /**
     * returns true if user-submitted POST token is identical to the previous stored session token.
     */
    function isCSFRTokenValid() {
        if(isset($_POST['csrf_token'])) {
            $user_token = $_POST['csrf_token'];
            $stored_token = $_SESSION['csrf_token'];
            return $user_token === $stored_token;
        } else {
            return false;
        }
    }

    /**
     * Token not valid, handle  this failure
     */
    function onCSFRTokenFailure() {
        if(!$this->isCSFRTokenValid()) {
            die("CSRF token validation failed.");
        }
    }

    /**
     * Optional check to see if token is also recent
     */
    function isCSFRTokenRecent() {
        $max_elapsed = 60 * 60 * 24; // 1 day
        if(isset($_SESSION['csrf_token_time'])) {
            $stored_time = $_SESSION['csrf_token_time'];
            return ($stored_time + $max_elapsed) >= time();
        } else {
            // Remove expired token
            $this->destroyCSFRToken();
            return false;
        }
    }

    function isRequestGet() {
        return $_SERVER['REQUEST_METHOD'] === 'GET';
    }

    function isRequestPost() {
        return $_SERVER['REQUEST_METHOD'] === 'POST';
    }

    /** Use with isRequestPost() to block posting from off-site forms */
    function isRequestSameDomain() {
        if(!isset($_SERVER['HTTP_REFERER'])) {
            // No refererer sent, so can't be same domain
            return false;
        } else {
            $referer_host = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
            $server_host = $_SERVER['HTTP_HOST'];

            // Uncomment for debugging
            // echo 'Request from: ' . $referer_host . "<br />";
            // echo 'Request to: ' . $server_host . "<br />";

            return ($referer_host == $server_host) ? true : false;
        }
    }

    /**
     * ENCRYPTION USAGE:
     *
     * Add a 32-character salt value (hard coded or stored in database)
     * to the string to make it harder to decrypt with brute force or
     * using rainbow tables.
     * $my_salt = 'SomeRandomString-hY5K92AzVnMYyT7';
     *
     * $string = 'This is a sample string in plain text.';
     * echo "Original: " . $string . "<br />";
     * echo "<br />";
     *
     * $encrypted_string = encrypt_string($my_salt, $string);
     * echo "Encrypted: ". $encrypted_string . "<br />";
     * echo "<br />";
     *
     * $decrypted_string = decrypt_string($my_salt, $encrypted_string);
     * echo "Decrypted: ". $decrypted_string . "<br />";
     * echo "<br />";
     *
     * Encrypted cookie functions
     * requires mcrypt: http://php.net/manual/en/book.mcrypt.php
     */
    function encrypt_string($salt, $string) {
        // Configuration (must match decryption)
        $cipher_type = MCRYPT_RIJNDAEL_256;
        $cipher_mode = MCRYPT_MODE_CBC;

        // Using initialization vector adds more security
        $iv_size = mcrypt_get_iv_size($cipher_type, $cipher_mode);
        $iv =  mcrypt_create_iv($iv_size, MCRYPT_RAND);

        $encrypted_string = mcrypt_encrypt($cipher_type, $salt, $string, $cipher_mode, $iv);

        // Return initialization vector + encrypted string
        // We'll need the $iv when decoding.
        return $iv . $encrypted_string;
    }

    function decrypt_string($salt, $iv_with_string) {
        // Configuration (must match encryption)
        $cipher_type = MCRYPT_RIJNDAEL_256;
        $cipher_mode = MCRYPT_MODE_CBC;

        // Extract the initialization vector from the encrypted string.
        // The $iv comes before encrypted string and has fixed size.
        $iv_size = mcrypt_get_iv_size($cipher_type, $cipher_mode);
        $iv = substr($iv_with_string, 0, $iv_size);
        $encrypted_string = substr($iv_with_string, $iv_size);

        $string = mcrypt_decrypt($cipher_type, $salt, $encrypted_string, $cipher_mode, $iv);
        return $string;
    }

    /** Encode after encryption to ensure encrypted characters are savable */
    function encrypt_string_and_encode($salt, $string) {
        return base64_encode(encrypt_string($salt, $string));
    }

    /** Decode before decryption */
    function decrypt_string_and_decode($salt, $string) {
        return decrypt_string($salt, base64_decode($string));
    }


    // * validate value has presence
    // use trim() so empty spaces don't count
    // use === to avoid false positives
    // empty() would consider "0" to be empty
    function has_presence($value) {
        $trimmed_value = trim($value);
        return isset($trimmed_value) && $trimmed_value !== "";
    }

    // * validate value has a format matching a regular expression
    // Be sure to use anchor expressions to match start and end of string.
    // (Use \A and \Z, not ^ and $ which allow line returns.)
    //
    // Example:
    // has_format_matching('1234', '/\d{4}/') is true
    // has_format_matching('12345', '/\d{4}/') is also true
    // has_format_matching('12345', '/\A\d{4}\Z/') is false
    function has_format_matching($value, $regex='//') {
        return preg_match($regex, $value);
    }


}



$secure = new SecureWebAppHelper;
if($secure->isRequestSameDomain()) {
    echo 'Same domain. POST requests should be allowed.<br />';
} else {
    echo 'Different domain. POST requests should be forbidden.<br />';
}
echo '<br />';
echo '<a href="">Same domain link</a><br />';