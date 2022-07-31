<?php
/**
 * Auth 
 * 
 * @author Tim Daniëls
 * @version 0.1.0
 */
namespace extensions;

use app\models\User;
use app\models\UserRole;
use app\models\Roles;
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
    public static function authenticate($userRole) {

        $user = new User();
        $user_role = new UserRole();
        $role = new Roles();
        $request = new Request();

        $userRole = $userRole['role'];

        $username = $request->get()['username'];
        $password = $request->get()['password'];

        $sql = DB::try()->select($user->t.'.'.$user->id, $user->t.'.'.$user->username, $user->t.'.'.$user->password, $role->t.'.'.$role->name)->from($user->t)->join($user_role->t)->on($user->t.'.'.$user->id, '=', $user_role->t.'.'.$user_role->user_id)->join($role->t)->on($user_role->t.'.'.$user_role->role_id, '=', $role->t.'.'.$role->id)->where($user->username, '=', $username)->and($role->name, '=', $userRole)->first();
        
        if(!empty($sql) && $sql !== null) {

            $fetched_password = $sql['password'];
            
            if(!password_verify($password, $fetched_password)) {
                return false;
            } else {
                Session::set('logged_in', true);
                Session::set('user_role', $sql['name']);
                Session::set('username', $sql['username']);
                return true;
            }
        }
    }
}