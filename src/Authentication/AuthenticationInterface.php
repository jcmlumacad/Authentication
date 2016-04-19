<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

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

    // --------------------------------------------------------------------------

    /**
     * Get users email.
     *
     * @return string
     */
    public function getEmail(): string;

    // --------------------------------------------------------------------------

    /**
     * Get a username.
     *
     * @return string
     */
    public function getUsername(): string;

    // --------------------------------------------------------------------------

    /**
     * Get the password.
     *
     * @return string
     */
    public function getPassword(): string;

    // --------------------------------------------------------------------------

    /**
     * Unset the username.
     *
     * @return AuthenticationInterface
     */
    public function unsetUsername(): AuthenticationInterface;

    // --------------------------------------------------------------------------

    /**
     * Unset a password.
     * provides unset for $password
     *
     * @return AuthenticationInterface
     */
    public function unsetPassword(): AuthenticationInterface;

    // --------------------------------------------------------------------------

    /**
     * Get the system type.
     *
     * @return string
     */
    public function getsystemType(): string;

    // --------------------------------------------------------------------------

    /**
     * Set email property.
     *
     * @throws throwInvalidArgumentExceptionError on non string value for $email
     * @param string  $email  A user email
     *
     * @return AuthenticationInterface
     */
    public function setEmail(string $email): AuthenticationInterface;

    // --------------------------------------------------------------------------

    /**
     * Get the error report.
     *
     * @return string
     */
    public function getErrorReport(): string;

    // --------------------------------------------------------------------------

    /**
     * Get the error number.
     *
     * @return int
     */
    public function getErrorNumber(): int;

    // --------------------------------------------------------------------------

    /**
     * Set user password.
     *
     * @throws \InvalidArgumentException on non string value for $password
     * @param string $password The user provided password
     *
     * @return AuthenticationInterface
     */
    public function setPassword(string $password): AuthenticationInterface;

    // --------------------------------------------------------------------------

    /**
     * Set username.
     *
     * Stores username in lowercase
     *
     * @throws \InvalidArgumentException on non string value for $username
     * @param string  $username  The user provided username
     *
     * @return AuthenticationInterface
     */
    public function setUsername(string $username): AuthenticationInterface;

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
    public function validatePassword(string $password = null): bool;

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
    public function validateUsername(string $userName = null): bool;

    // --------------------------------------------------------------------------

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
    public function authenticateDatabaseUser(string $email, string $password): bool;

    // --------------------------------------------------------------------------

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

    // --------------------------------------------------------------------------
}
