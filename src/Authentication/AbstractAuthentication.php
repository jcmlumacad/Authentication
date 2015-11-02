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
use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Encryption\EncryptionInterface;
use UCSDMath\Functions\ServiceFunctionsInterface;
use UCSDMath\DependencyInjection\ServiceRequestContainer;

/**
 * AbstractAuthentication provides an abstract base class implementation of {@link AuthenticationInterface}.
 * Primarily, this services the fundamental implementations for all Authentication classes.
 *
 * This component library is used to service basic authentication and authorization requirements
 * for user access to applications, methods, and information within the UCSDMath Framework.
 * Users in the system are provided with a Passport that defines them and their level of access
 * to the applications.
 *
 * Method list:
 *
 * @method AuthenticationInterface __construct();
 * @method void __destruct();
 * @method string getEmail();
 * @method string getUsername();
 * @method string getPassword();
 * @method AuthenticationInterface unsetUsername();
 * @method AuthenticationInterface unsetPassword();
 * @method string getsystemType();
 * @method AuthenticationInterface setEmail($email);
 * @method string getErrorReport();
 * @method string getErrorNumber();
 * @method AuthenticationInterface setPassword($password);
 * @method AuthenticationInterface setUsername($username);
 * @method AuthenticationInterface setErrorNumber($num = null);
 * @method boolean validatePassword($password = null);
 * @method boolean validateUsername($userName = null);
 * @method boolean authenticateDatabaseUser($email, $password);
 * @method boolean authenticateShibbolethUser($adusername = null);
 * @method boolean processPassword($email = null, $password = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractAuthentication implements AuthenticationInterface, ServiceFunctionsInterface
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
     *
     * @var    DatabaseInterface       $dbh                 A DatabaseInterface instance
     * @var    EncryptionInterface     $encryption          A EncryptionInterface instance
     * @var    string|null             $email               A primary user email
     * @var    string|null             $dbSalt              A database provided salt
     * @var    string|null             $username            A user provided username
     * @var    string|null             $password            A user provided password
     * @var    string|null             $systemType          A authentication ['DATABASE','SHIBBOLETH']
     * @var    string|null             $adusername          A user provided active directory username
     * @var    string|null             $dbUsername          A database provided username
     * @var    string|null             $dbPassword          A database provided password
     * @var    integer|null            $errorNumber         A returning error number
     * @var    string|null             $errorReport         A error feedback/text
     * @var    bool|null               $allowedAccess       A database provided access privlages
     * @var    integer                 $keyStretching       A time delay for password checking
     * @var    string|null             $randomPasswordSeed  A seed for generation of user password hashes
     * @var    array                   $storageRegister     A set of validation stored data elements
     * @static AuthenticationInterface $instance            A AuthenticationInterface instance
     * @static integer                 $objectCount         A AuthenticationInterface instance count
     */
    protected $dbh                = null;
    protected $encryption         = null;
    protected $email              = null;
    protected $dbSalt             = null;
    protected $username           = null;
    protected $password           = null;
    protected $systemType         = 'SHIBBOLETH';
    protected $adusername         = null;
    protected $dbUsername         = null;
    protected $dbPassword         = null;
    protected $errorNumber        = null;
    protected $errorReport        = null;
    protected $allowedAccess      = null;
    protected $keyStretching      = 20000;
    protected $randomPasswordSeed = '2ffd2dbeb8b292a845021cacfa9142b27';
    protected $storageRegister    = array();
    protected static $instance    = null;
    protected static $objectCount = 0;

    // --------------------------------------------------------------------------

    /**
     * Constructor.
     *
     * @param  DatabaseInterface    $dbh         A DatabaseInterface instance
     * @param  EncryptionInterface  $encryption  A EncryptionInterface instance
     *
     * @api
     */
    public function __construct(
        DatabaseInterface $dbh,
        EncryptionInterface $encryption
    ) {
        $this->setProperty('encryption', $encryption);
        $this->setProperty('dbh', $dbh);

        static::$instance = $this;
        static::$objectCount++;
    }

    // --------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        static::$objectCount--;
    }

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
    public function authenticateShibbolethUser($adusername = null)
    {
        $adusername = $adusername === null ? $this->getProperty('adusername'): $adusername;

        if (!$this->validateUsername($adusername)) {
            relayToRoute($this->config->getConst('REDIRECT_LOGIN').'index.php?v='.$this->encryption->numHash(4, 'encrypt').';');
        }

        $data = $this->dbh->getUserEmailAccount($adusername)->getResultDataSet();

        if (1 === $data['record_count']) {
            $this->setProperty('email', trim($data['email']));

            return true;
        } else {
            /** Database record not found for adusername. */
            $this->dbh->insertiNetRecordLog($adusername, '-- Login Error: Email from given adusername not found in database.(ADUSERNAME)');

            return false;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * Relay to location.
     *
     * @param string $destination  A routing location
     *
     * @return void
     */
    public function relayToRoute($destination)
    {
        header('Location: ' . $destination, true, 302);
        exit('Routing error...AbstractSession::relayToRoute()');
    }

    // --------------------------------------------------------------------------

    /**
     * Authenticate Database User
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
    public function authenticateDatabaseUser($email, $password)
    {
        $data = $this->dbh->getUserPassword($this->getProperty('username'))->getResultDataSet();

        /**
         * Username is an email address
         */
        $this->setEmail($this->getProperty('username'));

        if (1 !== $data['record_count']) {
            /**
             * Username not found in database
             */
            $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: Username not found in database.');

            return false;

        } elseif (true === $this->getUserFailedLoginAttempts($this->getProperty('username'))) {
            /**
             * Check failed login attempts; 2 hour lockout might apply
             */
            $this->dbh->insertiNetRecordLog($this->getProperty('username'),'-- Lockout: Account locked for 2 hrs; emailed user options.');

            return false;

        } else {
            /**
             * Apply key stretching
             */
            $salt = hash(static::DEFAULT_HASH, $data['uuid']);

            for ($i = 0; $i < (int) $this->getProperty('keyStretching'); $i++) {
                $password_hashed = hash(static::DEFAULT_HASH, $salt . $this->getProperty('password') . $salt);
            }

            if ((trim($data['passwd_db']) === trim($password_hashed))) {
                /**
                 * Authentication Passed -> OK
                 */
                $this->dbh->insertiNetRecordLog($this->getProperty('username'),'-- Login OK: Authention Granted Access.');

                return true;

            } else {
                /**
                 * Password is Incorrect (Failed Authentication)
                 */
                $this->dbh->insertiNetRecordLog($this->getProperty('username'),'-- Login Error: password incorrect.');
                $this->dbh->insertUserFailedAuthenticationAttempt($this->getProperty('username'),'-- Login Error: password incorrect.');

                return false;
            }
        }
    }

    // --------------------------------------------------------------------------

    /**
     * This method collects and stores an SHA512 Hash Authentication string
     * for database authentication.
     *
     * @param  string $email     A users email
     * @param  string $password  A users provided password
     *
     * @return bool
     */
    private function processPassword($email = null, $password = null)
    {
        $data = $this->dbh->getUserPassword($email)->getResultDataSet();

        if (1 !== $data['record_count']) {
            $this->dbh->insertiNetRecordLog($email,'-- Process Error: Email not found in database. Authentication::_processPassword();');
            return false;
        }

        $salt       = hash(static::DEFAULT_HASH, mb_strtoupper($data['uuid']), 'utf-8');
        $pass       = hash(static::DEFAULT_HASH, $email . $this->getProperty('randomPasswordSeed') . $password);
        $passwdHash = hash(static::DEFAULT_HASH, $salt . $pass . $salt);

        $this->dbh->updateUserPassword($email, $passwdHash) ? : trigger_error(197, FATAL);

        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * Unset a password.
     * provides unset for $password
     *
     * @return null
     */
    public function unsetPassword()
    {
        unset($this->{'password'});

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Get a username.
     *
     * @return string
     */
    public function getUsername()
    {
        return $this->{'username'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get users email.
     *
     * @return string
     */
    public function getEmail()
    {
        return $this->{'email'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the password.
     *
     * @return string
     */
    public function getPassword()
    {
        return $this->{'password'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the system type.
     *
     * @return string
     */
    public function getsystemType()
    {
        return $this->{'systemType'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the error report.
     *
     * @return string
     */
    public function getErrorReport()
    {
        return $this->getProperty('errorReport');
    }

    // --------------------------------------------------------------------------

    /**
     * Get the error number.
     *
     * @return integer
     */
    public function getErrorNumber()
    {
        return (int) $this->getProperty('errorNumber');
    }

    // --------------------------------------------------------------------------

    /**
     * Set a error number.
     *
     * @return integer
     */
    private function setErrorNumber($num = null)
    {
        $this->setProperty('errorNumber', (int) $num);
    }

    // --------------------------------------------------------------------------

    /**
     * Method implementations inserted.
     *
     * The notation below illustrates visibility: (+) @api, (-) protected or private.
     *
     * @method all();
     * @method init();
     * @method get($key);
     * @method has($key);
     * @method version();
     * @method getClassName();
     * @method getConst($key);
     * @method set($key, $value);
     * @method isString($str);
     * @method getInstanceCount();
     * @method getClassInterfaces();
     * @method __call($callback, $parameters);
     * @method getProperty($name, $key = null);
     * @method doesFunctionExist($functionName);
     * @method isStringKey($str, array $keys);
     * @method throwExceptionError(array $error);
     * @method setProperty($name, $value, $key = null);
     * @method throwInvalidArgumentExceptionError(array $error);
     */
    use ServiceFunctions;
}
