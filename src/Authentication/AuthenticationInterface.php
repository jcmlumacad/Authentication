<?php
declare(strict_types=1);

/*
 * This file is part of the UCSDMath package.
 *
 * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace UCSDMath\Authentication;

/**
 * AuthenticationInterface is the interface implemented by all Authentication classes.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
interface AuthenticationInterface
{
    /**
     * Constants.
     */
    const REQUIRED_PHP_VERSION = '7.0.0';
    const DEFAULT_CHARSET = 'UTF-8';

    public function getEmail();
    public function getUsername();
    public function getPassword();
    public function unsetUsername();
    public function unsetPassword();
    public function getsystemType();
    public function setEmail($email);
    public function getErrorReport();
    public function getErrorNumber();
    public function setPassword($password);
    public function setUsername($username);
    public function validatePassword($password = null);
    public function validateUsername($userName = null);
    public function authenticateDatabaseUser($email, $password);
    public function authenticateShibbolethUser($adusername = null);
}
