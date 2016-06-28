<?php

class PassHash
{
    private static $algo = '$2a';
    private static $cost = '$10';

    public static function UniqueSalt() {
        return substr(sha1(mt_rand()), 0, 22);
    }

    public static function Hash($password) {
        return crypt($password, self::$algo . self::$cost . '$' . self::UniqueSalt());
    }

    public static function CheckPassword($hash, $password) {
        $full_salt = substr($hash, 0, 29);
        $new_hash = crypt($password, $full_salt);
        return ($hash == $new_hash);
    }

}