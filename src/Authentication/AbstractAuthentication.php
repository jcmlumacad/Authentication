<?php/* * This file is part of the UCSDMath package. * * (c) UCSD Mathematics | Math Computing Support <mathhelp@math.ucsd.edu> * * For the full copyright and license information, please view the LICENSE * file that was distributed with this source code. */namespace UCSDMath\Authentication;use UCSDMath\Database\DatabaseInterface;use UCSDMath\Functions\ServiceFunctions;use UCSDMath\Encryption\EncryptionInterface;use UCSDMath\Functions\ServiceFunctionsInterface;use UCSDMath\DependencyInjection\ServiceRequestContainer;/** * AbstractAuthentication provides an abstract base class implementation of {@link AuthenticationInterface}. * Primarily, this services the fundamental implementations for all Authentication classes. * * This component library is used to service basic authentication and authorization requirements * for user access to applications, methods, and information within the UCSDMath Framework. * Users in the system are provided with a Passport that defines them and their level of access * to the applications. * * Method list: * * @method AuthenticationInterface __construct(); * @method void                    __destruct(); * @method string                  getEmail(); * @method string                  getUsername(); * @method string                  getPassword(); * @method AuthenticationInterface unsetUsername(); * @method AuthenticationInterface unsetPassword(); * @method string                  getsystemType(); * @method AuthenticationInterface setEmail($email); * @method string                  getErrorReport(); * @method string                  getErrorNumber(); * @method AuthenticationInterface setPassword($password); * @method AuthenticationInterface setUsername($username); * @method AuthenticationInterface setErrorNumber($num = null); * @method string                  getUserFailedLoginAttempts($email); * @method boolean                 validatePassword($password = null); * @method boolean                 validateUsername($userName = null); * @method boolean                 authenticateNISUser($username, $password); * @method boolean                 authenticateDatabaseUser($email, $password); * @method boolean                 authenticateShibbolethUser($adusername = null); * @method boolean                 processPassword($email = null, $password = null); * * @author Daryl Eisner <deisner@ucsd.edu> */abstract class AbstractAuthentication implements AuthenticationInterface, ServiceFunctionsInterface{    /**     * Constants.     *     * @var string VERSION  A version number     *     * @api     */    const VERSION = '1.4.0';    // --------------------------------------------------------------------------    /**     * Properties.     *     * @var    DatabaseInterface       $dbh                 A DatabaseInterface instance     * @var    EncryptionInterface     $encryption          A EncryptionInterface instance     * @var    string|null             $email               A primary user email     * @var    string|null             $dbSalt              A database provided salt     * @var    string|null             $username            A user provided username     * @var    string|null             $password            A user provided password     * @var    string|null             $systemType          A authentication ['NIS','DATABASE','SHIBBOLETH']     * @var    string|null             $adusername          A user provided active directory username     * @var    string|null             $dbUsername          A database provided username     * @var    string|null             $dbPassword          A database provided password     * @var    integer|null            $errorNumber         A returning error number     * @var    string|null             $errorReport         A error feedback/text     * @var    bool|null               $allowedAccess       A database provided access privlages     * @var    integer                 $keyStretching       A time delay for password checking     * @var    string|null             $randomPasswordSeed  A seed for generation of user password hashes     * @var    array                   $storageRegister     A set of validation stored data elements     * @static AuthenticationInterface $instance            A AuthenticationInterface instance     * @static integer                 $objectCount         A AuthenticationInterface instance count     */    protected $dbh                = null;    protected $encryption         = null;    protected $email              = null;    protected $dbSalt             = null;    protected $username           = null;    protected $password           = null;    protected $systemType         = 'SHIBBOLETH';    protected $adusername         = null;    protected $dbUsername         = null;    protected $dbPassword         = null;    protected $errorNumber        = null;    protected $errorReport        = null;    protected $allowedAccess      = null;    protected $keyStretching      = 20000;    protected $randomPasswordSeed = '2ffd2dbeb8b292a845021cacfa9142b27';    protected $storageRegister    = array();    protected static $instance    = null;    protected static $objectCount = 0;    // --------------------------------------------------------------------------    /**     * Constructor.     *     * @param  DatabaseInterface    $dbh         A DatabaseInterface instance     * @param  EncryptionInterface  $encryption  A EncryptionInterface instance     *     * @api     */    public function __construct(        DatabaseInterface $dbh,        EncryptionInterface $encryption    ) {        $this->setProperty('encryption', $encryption);        $this->setProperty('dbh', $dbh);        static::$instance = $this;        static::$objectCount++;    }    // --------------------------------------------------------------------------    /**     * Destructor.     *     * @api     */    public function __destruct()    {        static::$objectCount--;    }    // --------------------------------------------------------------------------    /**     * Authenticate Shibboleth User.     *     * @return bool     *     * @api     */    public function authenticateShibbolethUser($adusername = null)    {        /**         * @notes  Expected ErrorNumber Meaning:         *         *         -- AUTHENTICATION_PASSED         1         *         -- PASSWORD_INCORRECT            2         *         -- USERNAME_NOT_FOUND            3         *         -- USERNAME_BAD_STRUCTURE        4         *         -- PASSWORD_BAD_STRUCTURE        5         *         -- ACCOUNT_IS_LOCKED             6         *         -- OTHER_PROBLEMS                7         *         -- DB_DENIED_ENTRY_USER          8         *         -- DB_DENIED_ENTRY_MAINTENANCE   9         *         -- INVALID_REQUEST              10         */        $adusername = $adusername === null ? $this->getProperty('adusername'): $adusername;        $this->validateUsername($adusername)            ? null            : header(                'Location: '.                $this->config->getConst('REDIRECT_LOGIN').'index.php?v='.                $this->encryption->numHash(4, 'encrypt').';',                true,                302            );        $data = $this->dbh->getUserEmailAccount($adusername)            ? $this->dbh->getResultDataSet()            : trigger_error(187, FATAL);        if (1 === $data['record_count']) {            $this->setProperty('email', trim($data['email']));            $this->setProperty('errorNumber', 1);            unset($data);            return true;        } else {            /** Database record not found for adusername. */            $this->setErrorNumber(3);            $this->dbh->insertiNetRecordLog(                $adusername,                '-- Login Error: Email from given adusername not found in database.(ADUSERNAME)'            );            return false;        }    }    // --------------------------------------------------------------------------    /**     * Authenticate Database User     *     * @return bool     *     * @api     */    public function authenticateDatabaseUser($email, $password)    {        /**         * @notes  Expected ErrorNumber Meaning:         *         *         -- AUTHENTICATION_PASSED         1         *         -- PASSWORD_INCORRECT            2         *         -- USERNAME_NOT_FOUND            3         *         -- USERNAME_BAD_STRUCTURE        4         *         -- PASSWORD_BAD_STRUCTURE        5         *         -- ACCOUNT_IS_LOCKED             6         *         -- OTHER_PROBLEMS                7         *         -- DB_DENIED_ENTRY_USER          8         *         -- DB_DENIED_ENTRY_MAINTENANCE   9         *         -- INVALID_REQUEST              10         */        /**         * MySQL Database Authentication         */        $data = $this->dbh->getUserPassword($this->getProperty('username'))            ? $this->dbh->getResultDataSet()            : trigger_error(184, FATAL);        /**         * Username is an email address         */        $this->setEmail($this->getProperty('username'));        if (1 !== $data['record_count']) {            /**             * Username not found in database             */            $this->setErrorNumber(3);            $this->dbh->insertiNetRecordLog(                $this->getProperty('username'),                '-- Login Error: Username not found in database.'            );            return false;        } elseif (true === $this->getUserFailedLoginAttempts($this->getProperty('username'))) {            /**             * Check failed login attempts; 2 hour lockout might apply             */            $this->setErrorNumber(6);            $this->dbh->insertiNetRecordLog(                $this->getProperty('username'),                '-- Lockout: Account locked for 2 hrs; emailed user options.'            );            return false;        } else {            /**             * Apply key stretching             */            $salt = hash(static::DEFAULT_HASH, $data['uuid']);            for ($i = 0; $i < (int) $this->getProperty('keyStretching'); $i++) {                $password_hashed = hash(static::DEFAULT_HASH, $salt . $this->getProperty('password') . $salt);            }            if ((trim($data['passwd_db']) === trim($password_hashed))) {                /**                 * Authentication Passed -> OK                 */                $this->setErrorNumber(1);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('username'),                    '-- Login OK: Authention Granted Access.'                );                return true;            } else {                /**                 * Password is Incorrect (Failed Authentication)                 */                $this->setErrorNumber(2);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('username'),                    '-- Login Error: password incorrect.'                );                $this->dbh->insertUserFailedAuthenticationAttempt(                    $this->getProperty('username'),                    '-- Login Error: password incorrect.'                );                return false;            }        }    }    // --------------------------------------------------------------------------    /**     * Authenticate NIS User     *     * @return bool     *     * @api     */    public function authenticateNISUser($username, $password)    {        /**         * @notes  Expected ErrorNumber Meaning:         *         *         -- AUTHENTICATION_PASSED         1         *         -- PASSWORD_INCORRECT            2         *         -- USERNAME_NOT_FOUND            3         *         -- USERNAME_BAD_STRUCTURE        4         *         -- PASSWORD_BAD_STRUCTURE        5         *         -- ACCOUNT_IS_LOCKED             6         *         -- OTHER_PROBLEMS                7         *         -- DB_DENIED_ENTRY_USER          8         *         -- DB_DENIED_ENTRY_MAINTENANCE   9         *         -- INVALID_REQUEST              10         */        /**         * NIS System Authentication (NIS Maps)         *         * Function: To print or pull user keys from the department NIS map (shadow)         * When we ran as a CGI (in Perl) we gave specific sudo privlages to a user.         * We switched to that user to get the user's shadow by requesting:         *     `/usr/local/bin/sudo /bin/ypmatch dsmith passwd.adjunct.byname`         * this would return: dsmith:zMgGtTvVlLB:14251::::::         *         * Today (with PHP), Wilson suggested we use his written program         * to pull the same shadow information:         *    `/usr/local/bin/sudo /home/mpasswd/bin/getypshadow dsmith`         * which returns the same map.         *         * This should help authenticate against NIS until implementation of campus Shibboleth         */        $data = $this->dbh->getUserEmailAccount($this->getProperty('username'))            ? $this->dbh->getResultDataSet()            : trigger_error(187, FATAL);        $shadow = 'deisner:zMgGtTvVlLB:14251:::::: ';  // Example only        // $shadow = shell_exec('/usr/local/bin/sudo /home/mpasswd/bin/getypshadow '.$this->getProperty('username'));        if (1 !== $data['record_count']) {            /**             * Database record not found             */            $this->setErrorNumber(3);            $this->dbh->insertiNetRecordLog(                $this->getProperty('username'),                '-- Login Error: Email from given Username not found in database.(NIS)'            );            return false;        } else {            $this->setProperty('email', trim($data['email']));            unset($data);        }        if (empty($shadow)            || ! is_string($shadow)) {            /**             * Database record not found             */            $this->setErrorNumber(3);            $this->dbh->insertiNetRecordLog(                $this->getProperty('username'),                '-- Login Error: Username was not found on systems NIS Map.'            );            return false;        } elseif (true === $this->getUserFailedLoginAttempts($this->getProperty('email'))) {            /**             * Account Lock Check (too many failed login attempts)             *             * The account maybe locked for 2 hours.             * An email notice should also be sent to the account user with             * note explaining, unlock function option, and a password reset option.             * This should help limit brute force attacks.             */            $this->setErrorNumber(6);            $this->dbh->insertiNetRecordLog(                $this->getProperty('email'),                '-- Lockout: Account locked for 2 hrs; emailed user options.'            );            return false;        } else {            list($shadow_username, $shadow_passwd) = explode(':', $shadow);            if (crypt($this->getProperty('password'), trim($shadow_passwd)) === trim($shadow_passwd)) {                /**                 * Authentication Passed -> OK                 */                $this->setErrorNumber(1);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('email'),                    '-- Login OK: Authention Granted Access.'                );                /**                 * Collect Password Hashes (if backup is required)                 */                // $this->processPassword($this->getProperty('email'), $this->getProperty('password'));                return true;            } else {                /**                 * Password is Incorrect (Failed Authentication)                 */                $this->setErrorNumber(2);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('email'),                    '-- Login Error: Password is Incorrect (Failed Authentication).'                );                $this->dbh->insertUserFailedAuthenticationAttempt(                    $this->getProperty('email'),                    '-- Login Error: Password is Incorrect (Failed Authentication).'                );                return false;            }        }    }    // --------------------------------------------------------------------------    /**     * Accounts lockout threshold.     *     * Within the last 2 hours has there been 7 or more failed logins?     *     * @param string $email The user provided username     *     * @return string     */    public function getUserFailedLoginAttempts($email)    {        $hours = 3600 * (int) $this->getProperty('hours_unlock_login');        $data = $this->dbh->getUserFailedLoginAttempts($email, $hours)            ? $this->dbh->getResultDataSet()            : trigger_error(183, FATAL);        return $data['record_count'] >= (int) $this->getProperty('max_logins_allowed');    }    // --------------------------------------------------------------------------    /**     * Validate User Password.     *     * (                  -- Start of group     * (?=.*\d)           -- must contains one digit from 0-9     * (?=.*[a-z])        -- must contains one lowercase characters     * (?=.*[A-Z])        -- must contains one uppercase characters     * (?=.*[^\da-zA-Z])  -- must contains one non-alphanumeric characters     *  .                 -- match anything with previous condition checking     * {7,8}              -- length at least 7 characters and maximum of 8     * )                  -- End of group     *     * @notes  Must be 7 to 8 characters in length and contain 3 of the 4 items.     *     * @return bool     */    public function validatePassword($password = null)    {        if ('NIS' === $this->getProperty('systemType')) {            /**             * Complexity Requirement Policy (Patterns)             *   -- Minimum password length  :: 7             *   -- Maximum password length  :: 8             *   -- Complexity Requirements  :: (see above listing)             *   -- Maximum Password Age     :: N/A             *   -- Minimum Password Age     :: N/A             *   -- Enforce Password History :: N/A             */            $pattern1 = '/(?=.*[a-z])(?=.*[A-Z])(?=.*[^\da-zA-Z]).{7,8}/';            $pattern2 = '/(?=.*\d)(?=.*[A-Z])(?=.*[^\da-zA-Z]).{7,8}/';            $pattern3 = '/(?=.*\d)(?=.*[a-z])(?=.*[^\da-zA-Z]).{7,8}/';            $pattern4 = '/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{7,8}/';            if ((bool) preg_match($pattern1, trim($password))                || (bool) preg_match($pattern2, trim($password))                || (bool) preg_match($pattern3, trim($password))                || (bool) preg_match($pattern4, trim($password))) {                    return true;            } else {                $this->setErrorNumber(5);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('username'),                    '-- Login Error: Password is badly structured or not provided.'                );                return false;            }            /**             * Should never get here!             */            trigger_error(188, FATAL);        } elseif ('DATABASE' === $this->getProperty('systemType')) {            if ((bool) preg_match('/^[a-fA-F0-9]{128}$/', trim($password))                && 128 === mb_strlen(trim($password), 'UTF-8')            ) {                return true;            } else {                $this->setErrorNumber(5);                $this->dbh->insertiNetRecordLog(                    $this->getProperty('username'),                    '-- Login Error: Password is badly structured or not provided.'                );                return false;            }            /**             * Should never get here!             */            trigger_error(166, FATAL);        } else {            /**             * System Type Incorrect             */            trigger_error(166, FATAL);            return false;        }    }    // --------------------------------------------------------------------------    /**     * Validate Username.     *     *   -- Must start with a letter     *   -- Uppercase and lowercase letters accepted     *   -- 2-8 characters in length     *   -- Letters, numbers, underscores, dots, and dashes only     *   --     *   -- If a non-NIS system, an email is a preferred username     *     * @param string $userName The user provided username     *     * @return bool     */    public function validateUsername($userName = null)    {        /**         * Check Arguments         */        if (empty($userName)            || ! is_string($userName)) {                $this->setErrorNumber(4);                $this->dbh->insertiNetRecordLog($userName, '-- Login Error: Username not provided or bad parameter.');                return false;        }        if ('NIS' === $this->getProperty('systemType')) {            /**             * See notes above for regular expression requirements.             */            /**             *    /^[a-z\d_.-]{2,7}$/i             *    ||||  |   |||    |||             *    ||||  |   |||    ||i : case insensitive             *    ||||  |   |||    |/ : end of regex             *    ||||  |   |||    $ : end of text             *    ||||  |   ||{2,7} : repeated 2 to 20 times             *    ||||  |   |] : end character group             *    ||||  | _ : underscore, period, dash             *    ||||  \d : any digit             *    |||a-z: 'a' through 'z'             *    ||[ : start character group             *    |^ : beginning of text             *    / : regex start             */            if ((bool) preg_match(                '/^[a-z][a-z\d_.-]*$/i',                trim(mb_substr(trim(strtolower($userName)), 0, 8, 'utf-8'))            )) {                /**                 * Valid Username -> OK                 */                return true;            } else {                /**                 * Invalid Username -> Bad                 */                $this->setErrorNumber(4);                $this->dbh->insertiNetRecordLog(                    $userName,                    '-- Login Error: Username did not meet login requirements for NIS.'                );                return false;            }        } elseif ('DATABASE' === $this->getProperty('systemType')) {            if (filter_var(trim($userName), FILTER_VALIDATE_EMAIL) !== false                && mb_strlen(trim($userName), 'UTF-8') < 61                && mb_strlen(trim($userName), 'UTF-8') > 7            ) {                /**                 * Remove all illegal characters from Email string and compare                 */                $userNameCheck = filter_var(trim($userName), FILTER_SANITIZE_EMAIL);                $userNameCheck = mb_substr(trim($userNameCheck), 0, 60, 'utf-8');                if (trim($userName) !== $userNameCheck) {                    /**                     * Username/Email incorrectly structured                     */                    $this->setErrorNumber(4);                    $this->dbh->insertiNetRecordLog(                        $userName,                        '-- Login Error: Username problems during FILTER_SANITIZE_EMAIL.'                    );                    return false;                }                /**                 * Ensure our DNS record exists for the domain                 */                list($username, $domain) = explode('@', $userName);                return checkdnsrr($domain, 'MX') ? : false;            } else {                /**                 * Invalid Email Address                 */                $this->setErrorNumber(4);                $this->dbh->insertiNetRecordLog(                    $userName,                    '-- Login Error: Username did not validate.'                );                return false;            }        } elseif ('SHIBBOLETH' === $this->getProperty('systemType')) {            /**             *    /^[a-z\d_.-]{2,7}$/i             *    ||||  |   |||    |||             *    ||||  |   |||    ||i : case insensitive             *    ||||  |   |||    |/ : end of regex             *    ||||  |   |||    $ : end of text             *    ||||  |   ||{2,7} : repeated 2 to 20 times             *    ||||  |   |] : end character group             *    ||||  | _ : underscore, period, dash             *    ||||  \d : any digit             *    |||a-z: 'a' through 'z'             *    ||[ : start character group             *    |^ : beginning of text             *    / : regex start             */            if ((bool) preg_match(                '/^[a-z][a-z\d_.-]*$/i',                trim(mb_substr(trim(strtolower($userName)), 0, 64, 'utf-8'))            )) {                /**                 * Valid Username -> OK                 */                return true;            } else {                /**                 * Invalid Username -> Bad                 */                $this->setErrorNumber(4);                $this->dbh->insertiNetRecordLog(                    $userName,                    '-- Login Error: Username did not meet login requirements for AD Username.'                );                return false;            }        } else {            return false;        }    }    // --------------------------------------------------------------------------    /**     * This method collects and stores an SHA512 Hash Authentication string     * for database authentication.     *     * @param  string $email     A users email     * @param  string $password  A users provided password     *     * @return bool     *     * @throws \InvalidArgumentException on non string value for $email     * @throws \InvalidArgumentException on non string value for $password     */    private function processPassword($email = null, $password = null)    {        $this->isString($email) && filter_var($email, FILTER_VALIDATE_EMAIL)            ? null            : $this->throwInvalidArgumentExceptionError([                'datatype|string|email|{$email}',                __METHOD__,                __CLASS__, 'A097'            ]);        $this->isString($password)            ? null            : $this->throwInvalidArgumentExceptionError(['datatype|string{$password}', __METHOD__, __CLASS__, 'A102']);        $data = $this->dbh->getUserPassword($email)            ? $this->dbh->getResultDataSet()            : trigger_error(196, FATAL);        if (1 !== $data['record_count']) {            /**             * Email or Username not found in database             */            $this->dbh->insertiNetRecordLog(                $email,                '-- Process Error: Email not found in database. Authentication::_processPassword();'            );            return false;        }        $salt       = hash(static::DEFAULT_HASH, mb_strtoupper($data['uuid']), 'utf-8');        $pass       = hash(static::DEFAULT_HASH, $email . $this->getProperty('randomPasswordSeed') . $password);        $passwdHash = hash(static::DEFAULT_HASH, $salt . $pass . $salt);        $this->dbh->updateUserPassword($email, $passwdHash) ? : trigger_error(197, FATAL);        return true;    }    // --------------------------------------------------------------------------    /**     * Set user password.     *     * @throws \InvalidArgumentException on non string value for $password     * @param  string $password The user provided password     *     * @return AuthenticationInterface     */    public function setPassword($password)    {        $this->isString($password)            ? null            : $this->throwInvalidArgumentExceptionError([                'datatype|string|{$password}',                __METHOD__,                __CLASS__,                'A102'            ]);        $this->setProperty('password', trim($password));        return $this;    }    // --------------------------------------------------------------------------    /**     * Set username.     *     * Stores username in lowercase     *     * @throws \InvalidArgumentException on non string value for $username     * @param  string  $username  The user provided username     *     * @return AuthenticationInterface     */    public function setUsername($username)    {        $this->isString($username)            ? null            : $this->throwInvalidArgumentExceptionError([                'datatype|string|{$username}',                __METHOD__,                __CLASS__,                'A101'            ]);        $this->setProperty('username', strtolower(trim($username)));        return $this;    }    // --------------------------------------------------------------------------    /**     * Set email property.     *     * @throws throwInvalidArgumentExceptionError on non string value for $email     * @param  string  $email  A user email     *     * @return AuthenticationInterface     */    public function setEmail($email)    {        $this->isString($email) && filter_var($email, FILTER_VALIDATE_EMAIL)            ? null            : $this->throwInvalidArgumentExceptionError([                'datatype|string|{$email}',                __METHOD__,                __CLASS__,                'A026'            ]);        $this->setProperty('email', strtolower(trim($email)));        return $this;    }    // --------------------------------------------------------------------------    /**     * Unset the username.     *     * @return null     */    public function unsetUsername()    {        unset($this->{'username'});        return $this;    }    // --------------------------------------------------------------------------    /**     * Unset a password.     * provides unset for $password     *     * @return null     */    public function unsetPassword()    {        unset($this->{'password'});        return $this;    }    // --------------------------------------------------------------------------    /**     * Get a username.     *     * @return string     */    public function getUsername()    {        return $this->{'username'};    }    // --------------------------------------------------------------------------    /**     * Get users email.     *     * @return string     */    public function getEmail()    {        return $this->{'email'};    }    // --------------------------------------------------------------------------    /**     * Get the password.     *     * @return string     */    public function getPassword()    {        return $this->{'password'};    }    // --------------------------------------------------------------------------    /**     * Get the system type.     *     * @return string     */    public function getsystemType()    {        return $this->{'systemType'};    }    // --------------------------------------------------------------------------    /**     * Get the error report.     *     * @return string     */    public function getErrorReport()    {        return $this->getProperty('errorReport');    }    // --------------------------------------------------------------------------    /**     * Get the error number.     *     * @return integer     */    public function getErrorNumber()    {        return (int) $this->getProperty('errorNumber');    }    // --------------------------------------------------------------------------    /**     * Set a error number.     *     * @return integer     */    private function setErrorNumber($num = null)    {        $this->setProperty('errorNumber', (int) $num);    }    // --------------------------------------------------------------------------    /**     * Method implementations inserted.     *     * The notation below illustrates visibility: (+) @api, (-) protected or private.     *     * @method all();     * @method init();     * @method get($key);     * @method has($key);     * @method version();     * @method getClassName();     * @method getConst($key);     * @method set($key, $value);     * @method isString($string);     * @method getInstanceCount();     * @method getClassInterfaces();     * @method __call($callback, $parameters);     * @method getProperty($name, $key = null);     * @method doesFunctionExist($functionName);     * @method isStringKey($string, array $keys);     * @method throwExceptionError(array $error);     * @method setProperty($name, $value, $key = null);     * @method throwInvalidArgumentExceptionError(array $error);     */    use ServiceFunctions;}