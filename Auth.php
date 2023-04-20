<?php
/**
 * Auth 
 * 
 * @author Tim Daniëls
 */
namespace extensions;

use core\http\Request;
use database\DB;
use core\Session;

class Auth {

    /**
     * Authenticate & authorize users
     * 
     * @param array $roleType expects 'role' as key and value type of admin|normal
     * @example authenticate(array('role' => 'normal')) || authenticate(array('role' => 'admin'))
     * @return bool true|false
     */
    public static function authenticate($userRole = null) {

        $request = new Request();
        $username = $request->get()['username'];
        $password = $request->get()['password'];

        if($userRole !== null) {

            $userRoleType = $userRole['role'];

            $sql = DB::try()->select('users.id', 'users.username', 'users.password','roles.name')->from('users')->join('user_role')->on('users.id', '=','user_role.user_id')->join('roles')->on('user_role.role_id', '=', 'roles.id')->where('users.username', '=', $username)->and('roles.name', '=', $userRoleType)->first();
        } else {
            $sql = DB::try()->select('users.username', 'users.password')->from('users')->where('username', '=', $username)->first();
        }

        return self::verifyPassword($sql, $password);
    }

    /**
     * Verify user password
     * 
     * @param array $sql user database record
     * @param string $password html input password value
     * @return bool
     */
    public static function verifyPassword($sql, $password) {

        self::loginAttempt($sql);

        if(!empty($sql) && $sql !== null) {

            $fetched_password = $sql['password'];
            
            if(password_verify($password, $fetched_password) && Session::exists('failed_login_attempts_timestamp') === false) {

                Session::set('logged_in', true);
                Session::set('user_role', $sql['name']);
                Session::set('username', $sql['username']);
                Session::set('failed_login_attempt', 0);

                return true;
            } 
        } 
    }

    /**
     * Counting failded login attempts
     * 
     * @return string failed_login_attempt session value | failed_login_attempts_timestamp session value
     */
    public static function loginAttempt($sql) {

        self::checkTooManyLoginAttempts();

        if(empty($sql) || $sql === null || Session::exists('logged_in') === false) {

            if(Session::exists('failed_login_attempt') === true) {

                $attempt = Session::get('failed_login_attempt');
                $attempt++;

                if(Session::get('failed_login_attempt') > 2) {
                    
                    return Session::set('failed_login_attempts_timestamp', time());
                }

                return Session::set('failed_login_attempt', $attempt);
            }

            Session::set('failed_login_attempt', 1);
        }
    }

    /**
     * Setting timeout based on failed login attempts
     */
    public static function checkTooManyLoginAttempts() {

        if(Session::exists('failed_login_attempts_timestamp') === true) {

            $timeoutInSeconds = 5;
            $currentTime = time();
            $timestampFailedLoginAttempts = Session::get('failed_login_attempts_timestamp');
        
            if($currentTime - $timestampFailedLoginAttempts > $timeoutInSeconds) {
    
                Session::delete('failed_login_attempts_timestamp');
                Session::set('failed_login_attempt', 0);
            } 
        }
    }
}