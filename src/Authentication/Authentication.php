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
}
