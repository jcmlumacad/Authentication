<?php

/*
 * This file is part of the UCSDMath package.
 *
 * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

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
    const VERSION = '1.7.0';

    // --------------------------------------------------------------------------

    /**
     * Properties.
     */

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param DatabaseInterface    $dbh         A DatabaseInterface
     * @param EncryptionInterface  $encryption  A EncryptionInterface
     *
     * @api
     */
    public function __construct(DatabaseInterface $dbh, EncryptionInterface $encryption)
    {
        parent::__construct($dbh, $encryption);
    }

    // --------------------------------------------------------------------------
}
