# Vault

### Secure All The Things!

Vault is a team password/credential management solution built on top of the popular Laravel framework.  Securely store and share credentials of any kind across teams.

## Important - this is a work in progress

The current implementation does not utilise client-side encryption.  Whilst all _secrets_ are stored in an encrypted format in the database (with an optionally automatically rotating encryption key), all decryption happens on the server-side before sending the unencrypted data to the browser.  This is an early stage proof-of-concept with client-side encryption planned in the next iteration.  If running this set up you should, at a minimum, have and SSL certificate installed on the server with all traffic being transfered over HTTPS.

## System Requirements

The key system requirements are those needed to run any basic Laravel 5.3 application:

* PHP >= 5.6.4
* OpenSSL PHP Extension
* PDO PHP Extension
* Mbstring PHP Extension
* Tokenizer PHP Extension
* XML PHP Extension
* Composer (for installation)


TODO: the rest of the documentation...