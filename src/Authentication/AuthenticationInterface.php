<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) 2015-2017 UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace UCSDMath\Authentication;

/**
 * AuthenticationInterface is the interface implemented by all Authentication classes.
 *
 * Method list: (+) @api.
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 *
 * @api
 */
interface AuthenticationInterface
{
    /**
     * Constants.
     *
     * @var string FRAMEWORK_MINIMUM_PHP The framework's minimum supported PHP version
     * @var string DEFAULT_CHARSET       The character encoding for the system
     * @var string CRLF                  The carriage return line feed
     * @var bool   REQUIRE_HTTPS         The secure setting TLS/SSL site requirement
     * @var string DEFAULT_TIMEZONE      The local timezone for the server (or set in ini.php)
     */
    public const FRAMEWORK_MINIMUM_PHP = '7.1.0';
    public const DEFAULT_CHARSET       = 'UTF-8';
    public const CRLF                  = "\r\n";
    public const REQUIRE_HTTPS         = true;
    public const DEFAULT_TIMEZONE      = 'America/Los_Angeles';

    //--------------------------------------------------------------------------

    /**
     * Get users email.
     *
     * @return string
     */
    public function getEmail(): string;

    //--------------------------------------------------------------------------

    /**
     * Get a username.
     *
     * @return string
     */
    public function getUsername(): string;

    //--------------------------------------------------------------------------

    /**
     * Get the password.
     *
     * @return string
     */
    public function getPassword(): string;

    //--------------------------------------------------------------------------

    /**
     * Unset the username.
     *
     * @return AuthenticationInterface The current instance
     */
    public function unsetUsername(): AuthenticationInterface;

    //--------------------------------------------------------------------------

    /**
     * Unset a password.
     * provides unset for $password
     *
     * @return AuthenticationInterface The current instance
     */
    public function unsetPassword(): AuthenticationInterface;

    //--------------------------------------------------------------------------

    /**
     * Get the system type.
     *
     * @return string
     */
    public function getsystemType(): string;

    //--------------------------------------------------------------------------

    /**
     * Get the error report.
     *
     * @return string
     */
    public function getErrorReport(): string;

    //--------------------------------------------------------------------------

    /**
     * Get the error number.
     *
     * @return int
     */
    public function getErrorNumber(): int;

    //--------------------------------------------------------------------------

    /**
     * Set user password.
     *
     * @throws \InvalidArgumentException on non string value for $password
     * @param string $password The user provided password
     *
     * @return AuthenticationInterface The current instance
     */
    public function setPassword(string $password): AuthenticationInterface;

    //--------------------------------------------------------------------------

    /**
     * Set username.
     *
     * Stores username in lowercase
     *
     * @param string $username The user provided username
     *
     * @throws \InvalidArgumentException on non string value for $username
     *
     * @return AuthenticationInterface The current instance
     */
    public function setUsername(string $username): AuthenticationInterface;

    //--------------------------------------------------------------------------

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
    public function validatePassword(string $password = null): bool;

    //--------------------------------------------------------------------------

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
    public function validateUsername(string $userName = null): bool;

    //--------------------------------------------------------------------------

    /**
     * Authenticate Database User.
     *
     * @notes  Expected ErrorNumber Meaning:
     *
     *         -- AUTHENTICATION_PASSED         1
     *         -- PASSWORD_INCORRECT            2
     *         -- USERNAME_NOT_FOUND            3
     *         -- USERNAME_BAD_STRUCTURE        4
     *         -- PASSWORD_BAD_STRUCTURE        5
     *         -- ACCOUNT_IS_LOCKED             6
     *         -- OTHER_PROBLEMS                7
     *         -- DB_DENIED_ENTRY_USER          8
     *         -- DB_DENIED_ENTRY_MAINTENANCE   9
     *         -- INVALID_REQUEST              10
     *
     * @return bool
     *
     * @api
     */
    public function authenticateDatabaseUser(): bool;

    //--------------------------------------------------------------------------

    /**
     * Authenticate Shibboleth User.
     *
     * @notes  Expected ErrorNumber Meaning:
     *
     *         -- AUTHENTICATION_PASSED         1
     *         -- PASSWORD_INCORRECT            2
     *         -- USERNAME_NOT_FOUND            3
     *         -- USERNAME_BAD_STRUCTURE        4
     *         -- PASSWORD_BAD_STRUCTURE        5
     *         -- ACCOUNT_IS_LOCKED             6
     *         -- OTHER_PROBLEMS                7
     *         -- DB_DENIED_ENTRY_USER          8
     *         -- DB_DENIED_ENTRY_MAINTENANCE   9
     *         -- INVALID_REQUEST              10
     *
     * @return bool
     *
     * @api
     */
    public function authenticateShibbolethUser(string $adusername = null): bool;

    //--------------------------------------------------------------------------
}
