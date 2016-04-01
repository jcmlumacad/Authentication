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

use UCSDMath\Configuration\Config;
use UCSDMath\Database\DatabaseInterface;
use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Encryption\EncryptionInterface;
use UCSDMath\Functions\ServiceFunctionsInterface;

/**
 * AbstractAuthentication provides an abstract base class implementation of {@link AuthenticationInterface}.
 * Primarily, this services the fundamental implementations for all Authentication classes.
 *
 * This component library is used to service basic authentication and authorization requirements
 * for user access to applications, methods, and information within the UCSDMath Framework.
 * Users in the system are provided with a Passport that defines them and their level of access
 * to the applications.
 *
 * Method list: (+) @api, (-) protected or private visibility.
 *
 * (+) AuthenticationInterface __construct();
 * (+) void __destruct();
 * (+) string getEmail();
 * (+) string getUsername();
 * (+) string getPassword();
 * (+) AuthenticationInterface unsetUsername();
 * (+) AuthenticationInterface unsetPassword();
 * (+) string getsystemType();
 * (+) AuthenticationInterface setEmail($email);
 * (+) string getErrorReport();
 * (+) string getErrorNumber();
 * (+) AuthenticationInterface setPassword($password);
 * (+) AuthenticationInterface setUsername($username);
 * (+) AuthenticationInterface setErrorNumber($num = null);
 * (+) boolean validatePassword($password = null);
 * (+) boolean validateUsername($userName = null);
 * (+) boolean authenticateDatabaseUser($email, $password);
 * (+) boolean authenticateShibbolethUser($adusername = null);
 * (+) boolean processPassword($email = null, $password = null);
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
    const VERSION = '1.7.0';

    // --------------------------------------------------------------------------

    /**
     * Properties.
     *
     * @var    DatabaseInterface       $dbh                 A DatabaseInterface
     * @var    EncryptionInterface     $encryption          A EncryptionInterface
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
     * @var    int                     $keyStretching       A time delay for password checking
     * @var    string|null             $randomPasswordSeed  A seed for generation of user password hashes
     * @var    array                   $storageRegister     A set of validation stored data elements
     * @static AuthenticationInterface $instance            A AuthenticationInterface
     * @static int                     $objectCount         A AuthenticationInterface count
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
     * @param DatabaseInterface    $dbh         A DatabaseInterface
     * @param EncryptionInterface  $encryption  A EncryptionInterface
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
    public function authenticateShibbolethUser(string $adusername = null): bool
    {
        $adusername = $adusername === null ? $this->getProperty('adusername') : $adusername;

        if (!$this->validateUsername($adusername)) {
            relayToRoute(Config::REDIRECT_LOGIN . 'index.php?v=' . $this->encryption->numHash(4, 'encrypt') . ';');
        }

        $data = $this->dbh->getUserEmailAccount($adusername)->getResultDataSet();

        if (1 === $data['record_count']) {
            $this->setProperty('email', trim($data['email']));

            return true;
        } else {
            /* Database record not found for adusername. */
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
    public function relayToRoute(string $destination)
    {
        header('Location: ' . $destination, true, 302);
    }

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
    public function authenticateDatabaseUser(string $email, string $password): bool
    {
        $data = $this->dbh->getUserPassword($this->getProperty('username'))->getResultDataSet();

        /* Username is an email address */
        $this->setEmail($this->getProperty('username'));

        if (1 !== $data['record_count']) {
            /* Username not found in database */
            $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: Username not found in database.');

            return false;

        } else {
            /* Apply key stretching */
            $salt = hash(static::DEFAULT_HASH, $data['uuid']);
            $password_hashed = null;

            for ($i = 0; $i < (int) $this->getProperty('keyStretching'); $i++) {
                $password_hashed = hash(static::DEFAULT_HASH, $salt . $this->getProperty('password') . $salt);
            }

            if ((trim($data['passwd_db']) === trim($password_hashed))) {
                /**
                 * Authentication Passed -> OK.
                 */
                $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login OK: Authention Granted Access.');

                return true;

            } else {
                /**
                 * Password is Incorrect (Failed Authentication).
                 */
                $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: password incorrect.');
                $this->dbh->insertUserFailedAuthenticationAttempt($this->getProperty('username'), '-- Login Error: password incorrect.');

                return false;
            }
        }
    }

    // --------------------------------------------------------------------------

    /**
     * This method collects and stores an SHA512 Hash Authentication string
     * for database authentication.
     *
     * @param string $email     A users email
     * @param string $password  A users provided password
     *
     * @return bool
     */
    private function processPassword(string $email = null, string $password = null): bool
    {
        $data = $this->dbh->getUserPassword($email)->getResultDataSet();

        if (1 !== $data['record_count']) {
            $this->dbh->insertiNetRecordLog($email, '-- Process Error: Email not found in database. Authentication::_processPassword();');
            return false;
        }

        $salt       = hash(static::DEFAULT_HASH, mb_strtoupper($data['uuid']), 'UTF-8');
        $pass       = hash(static::DEFAULT_HASH, $email . $this->getProperty('randomPasswordSeed') . $password);
        $passwdHash = hash(static::DEFAULT_HASH, $salt . $pass . $salt);

        $this->dbh->updateUserPassword($email, $passwdHash) ?: trigger_error(197, FATAL);

        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * Unset a password.
     * provides unset for $password
     *
     * @return AuthenticationInterface
     */
    public function unsetPassword(): AuthenticationInterface
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
    public function getUsername(): string
    {
        return $this->{'username'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get users email.
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->{'email'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the password.
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->{'password'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the system type.
     *
     * @return string
     */
    public function getsystemType(): string
    {
        return $this->{'systemType'};
    }

    // --------------------------------------------------------------------------

    /**
     * Get the error report.
     *
     * @return string
     */
    public function getErrorReport(): string
    {
        return $this->getProperty('errorReport');
    }

    // --------------------------------------------------------------------------

    /**
     * Get the error number.
     *
     * @return int
     */
    public function getErrorNumber(): int
    {
        return (int) $this->getProperty('errorNumber');
    }

    // --------------------------------------------------------------------------

    /**
     * Set a error number.
     *
     * @return AuthenticationInterface
     */
    private function setErrorNumber($num = null): AuthenticationInterface
    {
        $this->setProperty('errorNumber', (int) $num);

        return $this;
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
    public function getUserFailedLoginAttempts(string $email): string
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
    public function validatePassword(string $password = null): bool
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

        } else {
            /**
             * System Type Incorrect.
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
    public function validateUsername(string $userName = null): bool
    {
        if (null === $userName) {
            $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username not provided or bad parameter.');

            return false;
        }

        if (! (bool) preg_match('/^[a-z][a-z\d_.-]*$/i', trim(mb_substr(trim(strtolower($userName)), 0, 64, 'UTF-8')))) {
            $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username did not meet login requirements for AD Username.');

            return false;
        }

        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * Set user password.
     *
     * @throws \InvalidArgumentException on non string value for $password
     * @param string $password The user provided password
     *
     * @return AuthenticationInterface
     */
    public function setPassword(string $password): AuthenticationInterface
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
     * @param string  $username  The user provided username
     *
     * @return AuthenticationInterface
     */
    public function setUsername(string $username): AuthenticationInterface
    {
        $this->setProperty('username', strtolower(trim($username)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Set email property.
     *
     * @throws throwInvalidArgumentExceptionError on non string value for $email
     * @param string  $email  A user email
     *
     * @return AuthenticationInterface
     */
    public function setEmail(string $email): AuthenticationInterface
    {
        $this->setProperty('email', strtolower(trim($email)));

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Unset the username.
     *
     * @return AuthenticationInterface
     */
    public function unsetUsername(): AuthenticationInterface
    {
        unset($this->{'username'});

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * (+) all();
     * (+) init();
     * (+) get($key);
     * (+) has($key);
     * (+) version();
     * (+) getClassName();
     * (+) getConst($key);
     * (+) set($key, $value);
     * (+) isString($str);
     * (+) getInstanceCount();
     * (+) getClassInterfaces();
     * (+) __call($callback, $parameters);
     * (+) getProperty($name, $key = null);
     * (+) doesFunctionExist($functionName);
     * (+) isStringKey($str, array $keys);
     * (+) throwExceptionError(array $error);
     * (+) setProperty($name, $value, $key = null);
     * (+) throwInvalidArgumentExceptionError(array $error);
     */
    use ServiceFunctions;

    // --------------------------------------------------------------------------
}
