# Introduction

CertSage was designed for people of all ages and experience levels who want an incredibly quick and easy way to acquire Let's Encrypt TLS/SSL certificates. CertSage is especially helpful if you are using a shared hosting plan that does not allow root access, such as with GoDaddy or tsoHost. It's free, of course!

# Requirements

PHP 7.0+

# Installation

Assuming that your domain name is `example.com`...

1. Download [certsage.php](certsage.php).
2. Upload `certsage.php` into the webroot directory of your website (e.g. `/public_html`) that contains the content accessed when visiting `http://example.com`.

# Certificate Acquisition

Assuming that your domain name is `example.com`...

1. Visit `http://example.com/certsage.php`.
2. Enter the (sub)domain names in the box, one per line, for which you wish to acquire a certificate (e.g. `example.com` and `www.example.com`).
3. Select your certificate Key Type.
4. Enter your password into the Password box from your `password.txt` file found in your `CertSage` data directory, which is located in the parent directory of the directory where you uploaded `certsage.php`.
5. Press the Acquire Staging Certificate button if you want to confirm that your CertSage installation is working properly or the Acquire Production Certificate button if you are confident that your CertSage installation is working properly.

> [!NOTE]
> If you pressed the Acquire Staging Certificate button in step 5, you will need to repeat the Certificate Acquisition steps with pressing the Acquire Production Certificate button in step 5.

# Certificate Installation in cPanel

1. Enter your password into the Password box from your `password.txt` file found in your `CertSage` data directory, which is located in the parent directory of the directory where you uploaded `certsage.php`.
2. Press the Install Certificate into cPanel button.

> [!NOTE]
> The first time you use CertSage to install a certificate into cPanel, CertSage sets up a cron job for you to help automatically renew your certificate when needed. If you don't use cPanel, you'll need to install your certificate using some other method and manage your own certificate renewals.