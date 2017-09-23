<?php

/**
 *  Testet ob ein User eingeloggt ist und lädt die entsprechenden Privilegien
 */
function load_auth() {
  global $user, $privileges;
  
  $user = null;
  if (isset($_SESSION['uid'])) {
    $user = sql_select("SELECT * FROM `User` WHERE `UID`='" . sql_escape($_SESSION['uid']) . "' LIMIT 1");
    if (count($user) > 0) {
      // User ist eingeloggt, Datensatz zur Verfügung stellen und Timestamp updaten
      list($user) = $user;
      sql_query("UPDATE `User` SET " . "`lastLogIn` = '" . time() . "'" . " WHERE `UID` = '" . sql_escape($_SESSION['uid']) . "' LIMIT 1;");
      $privileges = privileges_for_user($user['UID']);
      return;
    }
    unset($_SESSION['uid']);
  }
  
  // guest privileges
  $privileges = privileges_for_group(- 1);
}

/**
 * generate a salt (random string) of arbitrary length suitable for the use with crypt()
 */
function generate_salt($length = 16) {
  $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  $salt = "";
  for ($i = 0; $i < $length; $i ++) {
    $salt .= $alphabet[rand(0, strlen($alphabet) - 1)];
  }
  return $salt;
}

/**
 * set the password of a user
 */
function set_password($uid, $password) {
  global $crypt_alg;
  $result = sql_query("UPDATE `User` SET `Passwort` = '" . sql_escape(crypt($password, $crypt_alg . '$' . generate_salt(16) . '$')) . "', `password_recovery_token`=NULL WHERE `UID` = " . intval($uid) . " LIMIT 1");
  if ($result === false) {
    engelsystem_error('Unable to update password.');
  }
  return $result;
}

function check_user_existence($nick) {
  global $ldap;
  $db = sql_num_query("SELECT * FROM `User` WHERE `Nick`='" . sql_escape($nick) . "' LIMIT 1") > 0;
  if ($db) { return true; }
  if (isset($ldap) && $ldap['enabled'] == 1 && $ldap['verify_nicks']) {
    $ldap_conn = create_ldap_connection();
    $bind = @ldap_bind($ldap_conn, $ldap['bind_user'], $ldap['bind_pass']);
    $result = ldap_search($ldap_conn, $ldap['base_dn'], str_replace("%nick%", $nick, $ldap['search_filter']));
    $entries = ldap_get_entries($ldap_conn, $result);
    ldap_close($ldap_conn);
    if (count($entries) > 0) { return true; }
  }
  return false;
}

function register_ldap_user($nick) {
  global $ldap;
  $ldap_conn = create_ldap_connection();
  $bind = @ldap_bind($ldap_conn, $ldap['bind_user'], $ldap['bind_pass']);
  $result = ldap_search($ldap_conn, $ldap['base_dn'], str_replace("%nick%", $nick, $ldap['search_filter']));
  $entries = ldap_get_entries($ldap_conn, $result);
  ldap_close($ldap_conn);

  $prename = "";
  $lastname = "";
  $email = "";
  if (isset($ldap['entries']['prename'])) {
    if (isset($entries[0][$ldap['entries']['prename']][0])) {
      $prename = $entries[0][$ldap['entries']['prename']][0];
    }
  }
  if (isset($ldap['entries']['lastname'])) {
    if (isset($entries[0][$ldap['entries']['lastname']][0])) {
      $lastname = $entries[0][$ldap['entries']['lastname']][0];
    }
  }
  if (isset($ldap['entries']['email'])) {
    if (isset($entries[0][$ldap['entries']['email']][0])) {
      $email = $entries[0][$ldap['entries']['email']][0];
    }
  }

  sql_query("INSERT INTO `User` SET 
          `color`='" . sql_escape($default_theme) . "', 
          `Nick`='" . sql_escape($nick) . "', 
          `Vorname`='" . sql_escape($prename) . "', 
          `Name`='" . sql_escape($lastname) . "', 
          `Alter`='" . sql_escape("") . "', 
          `Telefon`='" . sql_escape("") . "', 
          `DECT`='" . sql_escape("-") . "', 
          `Handy`='" . sql_escape("") . "', 
          `email`='" . sql_escape($email) . "', 
          `email_shiftinfo`=" . sql_bool("1") . ", 
          `email_by_human_allowed`=" . sql_bool("1") . ",
          `jabber`='" . sql_escape("") . "',
          `Size`='" . sql_escape("L") . "', 
          `Passwort`='" . sql_escape("") . "', 
          `kommentar`='" . sql_escape("") . "', 
          `Hometown`='" . sql_escape("") . "', 
          `CreateDate`=NOW(), 
          `Sprache`='" . sql_escape($_SESSION["locale"]) . "',
          `arrival_date`='',
          `Gekommen` = 1,
          `planned_departure_date`='" . sql_escape("1540940400") . "',
          `planned_arrival_date`='" . sql_escape("0") . "'");

  $user_id = sql_id();
  sql_query("INSERT INTO `UserGroups` SET `uid`='" . sql_escape($user_id) . "', `group_id`=-2");

  engelsystem_log("User " . User_Nick_render(User($user_id)) . " signed up as: " . join(", ", $user_angel_types_info));
}

function create_ldap_connection() {
  global $ldap;
  $ldap_conn = ldap_connect($ldap['server']);
  ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
  ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);
  if (isset($ldap['starttls']) && $ldap['starttls']) {
    ldap_start_tls($ldap_conn);
  }
  return $ldap_conn;
}

/**
 * verify a password given a precomputed salt.
 * if $uid is given and $salt is an old-style salt (plain md5), we convert it automatically
 */
function verify_password($password, $salt, $uid = false) {
  global $crypt_alg, $ldap;
  $correct = false;
  if (isset($ldap) && $ldap['enabled'] == 1) {
    if ($salt == "*ldap*"){
      $ldap_conn = create_ldap_connection();
      $correct = @ldap_bind($ldap_conn, "uid=".$uid.",".$ldap['base_dn'], $password);
      ldap_close($ldap_conn);
      return $correct;
    }
  }
  if (substr($salt, 0, 1) == '$') { // new-style crypt()
    $correct = crypt($password, $salt) == $salt;
  } elseif (substr($salt, 0, 7) == '{crypt}') { // old-style crypt() with DES and static salt - not used anymore
    $correct = crypt($password, '77') == $salt;
  } elseif (strlen($salt) == 32) { // old-style md5 without salt - not used anymore
    $correct = md5($password) == $salt;
  }

  if ($correct && substr($salt, 0, strlen($crypt_alg)) != $crypt_alg && $uid) {
    // this password is stored in another format than we want it to be.
    // let's update it!
    // we duplicate the query from the above set_password() function to have the extra safety of checking the old hash
    sql_query("UPDATE `User` SET `Passwort` = '" . sql_escape(crypt($password, $crypt_alg . '$' . generate_salt() . '$')) . "' WHERE `UID` = " . intval($uid) . " AND `Passwort` = '" . sql_escape($salt) . "' LIMIT 1");
  }
  return $correct;
}

function privileges_for_user($user_id) {
  $privileges = [];
  $user_privs = sql_select("SELECT `Privileges`.`name` FROM `User` JOIN `UserGroups` ON (`User`.`UID` = `UserGroups`.`uid`) JOIN `GroupPrivileges` ON (`UserGroups`.`group_id` = `GroupPrivileges`.`group_id`) JOIN `Privileges` ON (`GroupPrivileges`.`privilege_id` = `Privileges`.`id`) WHERE `User`.`UID`='" . sql_escape($user_id) . "'");
  foreach ($user_privs as $user_priv) {
    $privileges[] = $user_priv['name'];
  }
  return $privileges;
}

function privileges_for_group($group_id) {
  $privileges = [];
  $groups_privs = sql_select("SELECT * FROM `GroupPrivileges` JOIN `Privileges` ON (`GroupPrivileges`.`privilege_id` = `Privileges`.`id`) WHERE `group_id`='" . sql_escape($group_id) . "'");
  foreach ($groups_privs as $guest_priv) {
    $privileges[] = $guest_priv['name'];
  }
  return $privileges;
}
?>
