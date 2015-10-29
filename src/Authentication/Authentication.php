<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace UCSDMath\Authentication;

use UCSDMath\Database\DatabaseInterface;
use UCSDMath\Encryption\EncryptionInterface;

/**
 * Authentication is the default implementation of {@link AuthenticationInterface} which
 * provides routine authentication methods that are commonly used throughout the framework.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
class Authentication extends AbstractAuthentication implements AuthenticationInterface
{
    /**
     * Constants.
     *
     * @var string VERSION  A version number
     *
     * @api
     */
    const VERSION = '1.4.0';

    // --------------------------------------------------------------------------

    /**
     * Properties.
     */

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param  DatabaseInterface    $dbh         A DatabaseInterface instance
     * @param  EncryptionInterface  $encryption  A EncryptionInterface instance
     *
     * @api
     */
    public function __construct(DatabaseInterface $dbh, EncryptionInterface $encryption) {
        parent::__construct($dbh, $encryption);
    }

    // --------------------------------------------------------------------------

    /**
     * Accounts lockout threshold.
     *
     * Within the last 2 hours has there been 7 or more failed logins?
     *
     * @param string $email The user provided username
     *
     * @return string
     */
    public function getUserFailedLoginAttempts($email)
    {
        $hours = 3600 * (int) $this->getProperty('hours_unlock_login');

        $data = $this->dbh->getUserFailedLoginAttempts($email, $hours)
            ? $this->dbh->getResultDataSet()
            : trigger_error(183, FATAL);

        return $data['record_count'] >= (int) $this->getProperty('max_logins_allowed');
    }

    // --------------------------------------------------------------------------

    /**
     * Validate User Password.
     *
     * (                  -- Start of group
     * (?=.*\d)           -- must contains one digit from 0-9
     * (?=.*[a-z])        -- must contains one lowercase characters
     * (?=.*[A-Z])        -- must contains one uppercase characters
     * (?=.*[^\da-zA-Z])  -- must contains one non-alphanumeric characters
     *  .                 -- match anything with previous condition checking
     * {7,8}              -- length at least 7 characters and maximum of 8
     * )                  -- End of group
     *
     * @notes  Must be 7 to 8 characters in length and contain 3 of the 4 items.
     *
     * @return bool
     */
    public function validatePassword($password = null)
    {
        if ('DATABASE' === $this->getProperty('systemType')) {
            if ((bool) preg_match('/^[a-fA-F0-9]{128}$/', trim($password))
                && 128 === mb_strlen(trim($password), 'UTF-8')
            ) {
                return true;

            } else {
                $this->dbh->insertiNetRecordLog(
                    $this->getProperty('username'),
                    '-- Login Error: Password is badly structured or not provided.'
                );

                return false;
            }

            /**
             * Should never get here!
             */
            trigger_error(166, FATAL);

        } else {
            /**
             * System Type Incorrect
             */
            trigger_error(166, FATAL);

            return false;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * Validate Username.
     *
     *   -- Must start with a letter
     *   -- Uppercase and lowercase letters accepted
     *   -- 2-8 characters in length
     *   -- Letters, numbers, underscores, dots, and dashes only
     *   --
     *   -- An email is a preferred username
     *
     * @param string $userName The user provided username
     *
     * @return bool
     */
    public function validateUsername($userName = null)
    {
        /**
         * Check Arguments
         */
        if (empty($userName)
            || ! is_string($userName)) {
                $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username not provided or bad parameter.');

                return false;
        }

        if ('DATABASE' === $this->getProperty('systemType')) {
            if (filter_var(trim($userName), FILTER_VALIDATE_EMAIL) !== false
                && mb_strlen(trim($userName), 'UTF-8') < 61
                && mb_strlen(trim($userName), 'UTF-8') > 7
            ) {
                /**
                 * Remove all illegal characters from Email string and compare
                 */
                $userNameCheck = filter_var(trim($userName), FILTER_SANITIZE_EMAIL);
                $userNameCheck = mb_substr(trim($userNameCheck), 0, 60, 'utf-8');

                if (trim($userName) !== $userNameCheck) {
                    /**
                     * Username/Email incorrectly structured
                     */
                    $this->dbh->insertiNetRecordLog($userName,'-- Login Error: Username problems during FILTER_SANITIZE_EMAIL.');

                    return false;
                }

                /**
                 * Ensure our DNS record exists for the domain
                 */
                list($username, $domain) = explode('@', $userName);

                return checkdnsrr($domain, 'MX') ? : false;

            } else {
                /**
                 * Invalid Email Address
                 */
                $this->dbh->insertiNetRecordLog($userName,'-- Login Error: Username did not validate.');

                return false;
            }

        } elseif ('SHIBBOLETH' === $this->getProperty('systemType')) {
            /**
             *    /^[a-z\d_.-]{2,7}$/i
             *    ||||  |   |||    |||
             *    ||||  |   |||    ||i : case insensitive
             *    ||||  |   |||    |/ : end of regex
             *    ||||  |   |||    $ : end of text
             *    ||||  |   ||{2,7} : repeated 2 to 20 times
             *    ||||  |   |] : end character group
             *    ||||  | _ : underscore, period, dash
             *    ||||  \d : any digit
             *    |||a-z: 'a' through 'z'
             *    ||[ : start character group
             *    |^ : beginning of text
             *    / : regex start
             */
            if ((bool) preg_match(
                '/^[a-z][a-z\d_.-]*$/i',
                trim(mb_substr(trim(strtolower($userName)), 0, 64, 'utf-8'))
            )) {
                /**
                 * Valid Username -> OK
                 */
                return true;

            } else {
                /**
                 * Invalid Username -> Bad
                 */
                $this->dbh->insertiNetRecordLog(
                    $userName,
                    '-- Login Error: Username did not meet login requirements for AD Username.'
                );

                return false;
            }

        } else {
            return false;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * Set user password.
     *
     * @throws \InvalidArgumentException on non string value for $password
     * @param  string $password The user provided password
     *
     * @return AuthenticationInterface
     */
    public function setPassword($password)
    {
        $this->setProperty('password', trim($password));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Set username.
     *
     * Stores username in lowercase
     *
     * @throws \InvalidArgumentException on non string value for $username
     * @param  string  $username  The user provided username
     *
     * @return AuthenticationInterface
     */
    public function setUsername($username)
    {
        $this->setProperty('username', strtolower(trim($username)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Set email property.
     *
     * @throws throwInvalidArgumentExceptionError on non string value for $email
     * @param  string  $email  A user email
     *
     * @return AuthenticationInterface
     */
    public function setEmail($email)
    {
        $this->setProperty('email', strtolower(trim($email)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Unset the username.
     *
     * @return null
     */
    public function unsetUsername()
    {
        unset($this->{'username'});

        return $this;
    }
}
