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
3. Press the Acquire Staging Certificate button if you want to confirm that your CertSage installation is working properly or the Acquire Production Certificate button if you are confident that your CertSage installation is working properly.

> [!NOTE]
> If you pressed the Acquire Staging Certificate button in step 3, you will need to repeat the Certificate Acquisition steps with pressing the Acquire Production Certificate button in step 3.

# Certificate Installation in cPanel

1. Open cPanel in your web browser.
2. Scroll to the FILES section.
3. Click on File Manager, which should open in a new tab.
4.  Open the `CertSage` data directory.
5. Click on the `certificate.crt` file.
6. Click *Edit*.
7. Copy the first certificate in the file including its header and footer.
8. Click *Close*.
9. Switch back to the cPanel tab.
10. Scroll to the SECURITY section.
11. Click on SSL/TLS (**not** SSL/TLS Status).
12. Scroll to the INSTALL AND MANAGE SSL FOR YOUR SITE (HTTPS) section.
13. Click on *Manage SSL sites.*
14. Scroll to the Domain section.
15. Select your domain name in the drop-down list.
16. Paste your certificate in the Certificate box.
17. Switch back to the File Manager tab.
18. Click on the `certificate.key` file.
19. Click *Edit*.
20. Copy the private key in the file including its header and footer.
21. Click *Close*.
22. Switch back to the cPanel tab.
23. Paste your private key in the Private Key box.
24. Click *Install Certificate*.

# HTTP to HTTPS Redirection in cPanel

1. Open cPanel in your web browser.
2. Scroll to the DOMAINS section.
3. Click on Domains.
4. Expand the section for your domain name.
5. Switch *Force HTTPS Redirect* to *On*.
