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

use UCSDMath\Database\DatabaseInterface;
use UCSDMath\Encryption\EncryptionInterface;

/**
 * Authentication is the default implementation of {@link AuthenticationInterface} which
 * provides routine Authentication methods that are commonly used in the framework.
 *
 * {@link AbstractAuthentication} is basically a base class for various authentication routines
 * which this class extends.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) AuthenticationInterface __construct();
 * (+) void __destruct();
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
class Authentication extends AbstractAuthentication implements AuthenticationInterface
{
    /**
     * Constants.
     *
     * @var string VERSION The version number
     *
     * @api
     */
    public const VERSION = '1.20.0';

    //--------------------------------------------------------------------------

    /**
     * Properties.
     */

    //--------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param DatabaseInterface   $dbh        The DatabaseInterface
     * @param EncryptionInterface $encryption The EncryptionInterface
     *
     * @api
     */
    public function __construct(DatabaseInterface $dbh, EncryptionInterface $encryption)
    {
        parent::__construct($dbh, $encryption);
    }

    //--------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        parent::__destruct();
    }

    //--------------------------------------------------------------------------
}
