<?php
// Reset token functions

// This function generates a string that can be
// used as a reset token.
function resetToken() {
	return md5(uniqid(rand()));
}

// Looks up a user and sets their reset_token to
// the given value. Can be used both to create and
// to delete the token.
function setUserResetToken($username, $token_value) {
	$user = find_one_in_fake_db('users', 'username', sql_prep($username));

	if($user) {
		$user['reset_token'] = $token_value;
		update_record_in_fake_db('users', 'username', $user);
		return true;
	} else {
		return false;
	}
}

// Add a new reset token to the user
function createResetToken($username) {
	$token = resetToken();
	return setUserResetToken($username, $token);
}

// Remove any reset token for this user.
function deleteResetToken($username) {
	$token = null;
	return setUserResetToken($username, $token);
}

// Returns the user record for a given reset token.
// If token is not found, returns null.
function findUserWithToken($token) {
	if(!has_presence($token)) {
		// We were expecting a token and didn't get one.
		return null;
	} else {
		$user = find_one_in_fake_db('users', 'reset_token', sql_prep($token));
		// Note: find_one_in_fake_db returns null if not found.
		return $user;
	}
}

// A function to email the reset token to the email
// address on file for this user.
// This is a placeholder since we don't have email
// abilities set up in the demo version.
function email_reset_token($username) {
	$user = find_one_in_fake_db('users', 'username', sql_prep($username));

	if($user) {
		// This is where you would connect to your emailer
		// and send an email with a URL that includes the token.
		return true;
	} else {
		return false;
	}
}

function sql_prep($string) {
    global $database;
    if($database) {
        return mysqli_real_escape_string($database, $string);
    } else {
        // addslashes is almost the same, but not quite as secure.
        // Fallback only when there is no database connection available.
        return addslashes($string);
    }
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

?>
