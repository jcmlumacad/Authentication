<?php/* * This file is part of the UCSDMath package. * * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu> * * For the full copyright and license information, please view the LICENSE * file that was distributed with this source code. */namespace UCSDMath\Authentication;use UCSDMath\Database\DatabaseInterface;use UCSDMath\Encryption\EncryptionInterface;/** * Authentication is the default implementation of {@link AuthenticationInterface} which * provides routine authentication methods that are commonly used throughout the framework. * * @author Daryl Eisner <deisner@ucsd.edu> * * @api */class Authentication extends AbstractAuthentication implements AuthenticationInterface{    /**     * Constants.     */    const VERSION = '1.0.2';    /**     * Properties.     */    /**     * Constructor.     *     * @param  DatabaseInterface   $dbh         A DatabaseInterface instance     * @param  EncryptionInterface $encryption  A EncryptionInterface instance     *     * @api     */    public function __construct(        DatabaseInterface $dbh,        EncryptionInterface $encryption    ) {        parent::__construct($dbh, $encryption);    }}