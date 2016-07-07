# Authentication
<table border="0">
  <tr>
    <td width="310"><img height="160" width="310"alt="UCSDMath - Mathlink" src="https://github.com/ucsdmath/Testing/blob/master/ucsdmath-logo.png"></td>
    <td><h3>A Development Project in PHP</h3><p><strong>UCSDMath</strong> provides a testing framework for general internal Intranet software applications for the UCSD, Department of Mathematics. This is used for development and testing only. [not for production]</p>

<center>
<table style="width:380px;"><tr>
    <td width="130">Travis CI</td><td width="250">SensioLabs</td>
</tr>
<tr><td width="130"><a href="https://travis-ci.org/ucsdmath/Authentication">
<img style="float: left; margin: 0px 0px 15px 15px;" src="https://travis-ci.org/ucsdmath/Authentication.svg?branch=master"></a></td>
<td width="250" align="center">
<a href="https://insight.sensiolabs.com/projects/84fe033b-3755-4a24-85d6-1dd5bbe43b4d">
<img src="https://insight.sensiolabs.com/projects/84fe033b-3755-4a24-85d6-1dd5bbe43b4d/big.png" style="float: right; margin: 0px 0px 15px 15px;" width="212" height="51"></a></td>
</tr></table>
</center>
</td></tr></table>

|Scrutinizer|Latest|PHP|Usage|Development|Code Quality|License|
|-----------|------|---|-----|-----------|------------|-------|
|[![Build Status](https://scrutinizer-ci.com/g/ucsdmath/Authentication/badges/build.png?b=master)](https://scrutinizer-ci.com/g/ucsdmath/Authentication/build-status/master)|[![Latest Stable Version](https://poser.pugx.org/ucsdmath/Authentication/v/stable)](https://packagist.org/packages/ucsdmath/Authentication)|[![Minimum PHP Version](https://img.shields.io/badge/php-%3E%3D%207.0-8892BF.svg)](https://php.net/)|[![Total Downloads](https://poser.pugx.org/ucsdmath/Authentication/downloads)](https://packagist.org/packages/ucsdmath/Authentication)|[![Latest Unstable Version](https://poser.pugx.org/ucsdmath/Authentication/v/unstable)](https://packagist.org/packages/ucsdmath/Authentication)|[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/ucsdmath/Authentication/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/ucsdmath/Authentication/?branch=master)|[![License](https://poser.pugx.org/ucsdmath/Authentication/license)](https://packagist.org/packages/ucsdmath/Authentication)|

Authentication is a testing and development library only. This is not to be used in a production.
Many features of this component have not been developed but are planned for future implementation.  UCSDMath components are written to be adapters of great developments such as Symfony, Twig, Doctrine, etc. This is a learning and experimental library only.

Copy this software from:
- [Packagist.org](https://packagist.org/packages/ucsdmath/Authentication)
- [Github.com](https://github.com/ucsdmath/Authentication)

## Installation using [Composer](http://getcomposer.org/)
You can install the class ```Authentication``` with Composer and Packagist by adding the ucsdmath/authentication package to your composer.json file:

```
"require": {
    "php": "^7.0",
    "ucsdmath/authentication": "dev-master"
},
```
Or you can add the class directly from the terminal prompt:

```bash
$ composer require ucsdmath/authentication
```

## Usage

``` php
$auth = new \UCSDMath\Authentication\Authentication();
```

## Documentation

No documentation site available at this time.
<!-- [Check out the documentation](http://math.ucsd.edu/~deisner/documentation/Authentication/) -->

## Testing

``` bash
$ phpunit
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email deisner@ucsd.edu instead of using the issue tracker.

## Credits

- [Daryl Eisner](https://github.com/UCSDMath)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
