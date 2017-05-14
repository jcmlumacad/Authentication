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

use UCSDMath\Configuration\Config;
use UCSDMath\Database\DatabaseInterface;
use UCSDMath\Functions\ServiceFunctions;
use UCSDMath\Encryption\EncryptionInterface;
use UCSDMath\Functions\ServiceFunctionsInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * AbstractAuthentication provides an abstract base class implementation of {@link AuthenticationInterface}.
 * This service groups a common code base implementation that Authentication extends.
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
 * (+) int getErrorNumber();
 * (+) string getPassword();
 * (+) string getUsername();
 * (+) string getsystemType();
 * (+) string getErrorReport();
 * (+) AuthenticationInterface unsetPassword();
 * (+) AuthenticationInterface unsetUsername();
 * (+) bool validatePassword(string $password = null);
 * (+) bool validateUsername(string $userName = null);
 * (+) AuthenticationInterface setPassword(string $password);
 * (+) AuthenticationInterface setUsername(string $username);
 * (+) bool authenticateShibbolethUser(string $adusername = null);
 * (+) void requestRoute(string $destination, bool $trailFix = false);
 * (+) bool authenticateDatabaseUser(string $email, string $password);
 * (-) string applyKeyStretching($data);
 * (-) AuthenticationInterface setErrorNumber($num = null);
 * (-) bool processPassword(string $email = null, string $password = null);
 *
 * @author Daryl Eisner <deisner@ucsd.edu>
 */
abstract class AbstractAuthentication implements AuthenticationInterface, ServiceFunctionsInterface
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
     *
     * @var    DatabaseInterface       $dbh                The DatabaseInterface
     * @var    EncryptionInterface     $encryption         The EncryptionInterface
     * @var    string                  $email              The primary user email
     * @var    string                  $username           The user provided username
     * @var    string                  $password           The user provided password
     * @var    string                  $systemType         The authentication ['DATABASE','SHIBBOLETH']
     * @var    string                  $adusername         The user provided active directory username
     * @var    int                     $errorNumber        The returning error number
     * @var    string                  $errorReport        The error feedback/text
     * @var    int                     $keyStretching      The time delay for password checking
     * @var    string                  $randomPasswordSeed The seed for generation of user password hashes
     * @static AuthenticationInterface $instance           The static instance AuthenticationInterface
     * @static int                     $objectCount        The static count of AuthenticationInterface
     * @var    iterable                $storageRegister    The stored set of data structures used by this class
     */
    protected $dbh                = null;
    protected $encryption         = null;
    protected $email              = null;
    protected $username           = null;
    protected $password           = null;
    protected $systemType         = 'SHIBBOLETH';
    protected $adusername         = null;
    protected $errorNumber        = null;
    protected $errorReport        = null;
    protected $keyStretching      = 20000;
    protected $randomPasswordSeed = '2ffd2dbeb8b292a845021cacfa9142b27';
    protected static $instance    = null;
    protected static $objectCount = 0;
    protected $storageRegister    = [];

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
        $this->setProperty('dbh', $dbh)->setProperty('encryption', $encryption);
    }

    //--------------------------------------------------------------------------

    /**
     * Destructor.
     *
     * @api
     */
    public function __destruct()
    {
        static::$objectCount--;
    }

    //--------------------------------------------------------------------------

    /**
     * Authenticate Shibboleth User.
     *
     * @param string $adusername The campus AD Username
     *
     * @return bool
     *
     * @api
     */
    public function authenticateShibbolethUser(string $adusername = null): bool
    {
        $adusername = null === $adusername ? $this->getProperty('adusername') : $adusername;
        $this->validateUsername($adusername)
            ?: requestRoute(Config::REDIRECT_LOGIN.'index.php?v='.$this->encryption->numHash(4, 'encrypt').';');
        $data = $this->dbh->getEmailAddress($adusername)->getRecord();
        if (1 === $data['record_count']) {
            $this->setProperty('email', trim($data['email']));
            return true;
        } else {
            $this->dbh->insertiNetRecordLog($adusername, '-- Login Error: Email from given adusername not found in personnel database.(ADUSERNAME)');
            return false;
        }
    }

    //--------------------------------------------------------------------------

    /**
     * Route to location (RedirectResponse extends Response).
     *
     * @param string $destination The routing location
     * @param bool   $trailFix    The fix for the trailing slash
     *
     * @return void
     */
    public function requestRoute(string $destination, bool $trailFix = false): void
    {
        $response = true === $trailFix
            ? new RedirectResponse(rtrim($destination, '/\\').'/')
            : new RedirectResponse($destination);
        $response->send();
    }

    //--------------------------------------------------------------------------

    /**
     * Authenticate Database User.
     *
     * @return bool
     *
     * @api
     */
    public function authenticateDatabaseUser(): bool
    {
        $data = $this->dbh->getUserPassword($this->getProperty('username'))->getRecords();
        $this->setProperty('email', strtolower(trim($this->getProperty('username'))));
        if (1 === $data['record_count']) {
            $passwordHashed = $this->applyKeyStretching($data);
            if ((trim($data['passwd_db']) === trim($passwordHashed))) {
                $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login OK: Authention Granted Access.');

                return true;
            }
            $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: password incorrect.');

            return false;
        } else {
            $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: Username not found in database.');

            return false;
        }
    }

    //--------------------------------------------------------------------------

    /**
     * This is to slow down authentication processes.
     *
     * @return string
     */
    private function applyKeyStretching($data): string
    {
        $salt = hash(static::DEFAULT_HASH, $data['uuid']);
        $passwordHashed = null;
        for ($i = 0; $i < (int) $this->getProperty('keyStretching'); $i++) {
            $passwordHashed = hash(static::DEFAULT_HASH, $salt.$this->getProperty('password').$salt);
        }

        return $passwordHashed;
    }

    //--------------------------------------------------------------------------

    /**
     * This method collects and stores an SHA512 Hash Authentication string
     * for database authentication.
     *
     * @param string $email    The users email
     * @param string $password The users provided password
     *
     * @return bool
     */
    protected function processPassword(string $email = null, string $password = null): bool
    {
        $data = $this->dbh->getUserPassword($email)->getRecords();
        if (1 !== $data['record_count']) {
            $this->dbh->insertiNetRecordLog($email, '-- Process Error: Email not found in database. Authentication::_processPassword();');
            return false;
        }
        $salt       = hash(static::DEFAULT_HASH, mb_strtoupper($data['uuid']), 'UTF-8');
        $pass       = hash(static::DEFAULT_HASH, $email.$this->getProperty('randomPasswordSeed').$password);
        $passwdHash = hash(static::DEFAULT_HASH, $salt.$pass.$salt);
        $this->dbh->updateUserPassword($email, $passwdHash) ?: trigger_error(197, FATAL);

        return true;
    }

    //--------------------------------------------------------------------------

    /**
     * Unset a password.
     * provides unset for $password
     *
     * @return AuthenticationInterface The current instance
     */
    public function unsetPassword(): AuthenticationInterface
    {
        unset($this->{'password'});

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Get a username.
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->{'username'};
    }

    //--------------------------------------------------------------------------

    /**
     * Get users email.
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->{'email'};
    }

    //--------------------------------------------------------------------------

    /**
     * Get the password.
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->{'password'};
    }

    //--------------------------------------------------------------------------

    /**
     * Get the system type.
     *
     * @return string
     */
    public function getsystemType(): string
    {
        return $this->{'systemType'};
    }

    //--------------------------------------------------------------------------

    /**
     * Get the error report.
     *
     * @return string
     */
    public function getErrorReport(): string
    {
        return $this->getProperty('errorReport');
    }

    //--------------------------------------------------------------------------

    /**
     * Get the error number.
     *
     * @return int
     */
    public function getErrorNumber(): int
    {
        return (int) $this->getProperty('errorNumber');
    }

    //--------------------------------------------------------------------------

    /**
     * Set a error number.
     *
     * @return AuthenticationInterface The current instance
     */
    protected function setErrorNumber($num = null): AuthenticationInterface
    {
        $this->setProperty('errorNumber', (int) $num);

        return $this;
    }

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
    public function validatePassword(string $password = null): bool
    {
        if (!(bool) (preg_match('/^[a-fA-F0-9]{128}$/', trim($password)) && 128 === mb_strlen(trim($password), 'UTF-8'))) {
            $this->dbh->insertiNetRecordLog($this->getProperty('username'), '-- Login Error: Password is badly structured or not provided.');

            return false;
        }

        return true;
    }

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
    public function validateUsername(string $userName = null): bool
    {
        if (null === $userName) {
            $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username not provided or bad parameter.');
            return false;
        }
        if (!(bool) preg_match('/^[a-z][a-z\d_.-]*$/i', trim(mb_substr(trim(strtolower($userName)), 0, 64, 'UTF-8')))) {
            $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username did not meet login requirements for AD Username.');
            return false;
        }

        return true;
    }

    //--------------------------------------------------------------------------

    /**
     * Set user password.
     *
     * @throws \InvalidArgumentException on non string value for $password
     * @param string $password The user provided password
     *
     * @return AuthenticationInterface The current instance
     */
    public function setPassword(string $password): AuthenticationInterface
    {
        $this->setProperty('password', trim($password));

        return $this;
    }

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
    public function setUsername(string $username): AuthenticationInterface
    {
        $this->setProperty('username', strtolower(trim($username)));

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Unset the username.
     *
     * @return AuthenticationInterface The current instance
     */
    public function unsetUsername(): AuthenticationInterface
    {
        unset($this->{'username'});

        return $this;
    }

    //--------------------------------------------------------------------------

    /**
     * Method implementations inserted:
     *
     * Method list: (+) @api, (-) protected or private visibility.
     *
     * (+) iterable all();
     * (+) object init();
     * (+) string version();
     * (+) bool isString($str);
     * (+) bool has(string $key);
     * (+) string getClassName();
     * (+) int getInstanceCount();
     * (+) mixed getConst(string $key);
     * (+) iterable getClassInterfaces();
     * (+) bool isValidUuid(string $uuid);
     * (+) bool isValidEmail(string $email);
     * (+) bool isValidSHA512(string $hash);
     * (+) bool doesFunctionExist(string $functionName);
     * (+) bool isStringKey(string $str, iterable $keys);
     * (+) mixed get(string $key, string $subkey = null);
     * (+) mixed getProperty(string $name, string $key = null);
     * (+) mixed __call(string $callback, iterable $parameters);
     * (+) object set(string $key, $value, string $subkey = null);
     * (+) object setProperty(string $name, $value, string $key = null);
     * (-) Exception throwExceptionError(iterable $error);
     * (-) InvalidArgumentException throwInvalidArgumentExceptionError(iterable $error);
     */
    use ServiceFunctions;

    //--------------------------------------------------------------------------
}
