# passwd.trade

passwd.trade is a self-destructing secure password transfer service.

## Technologies Used

The project runs on Apache, PHP, and MySQL.

## Database Management

passwd.trade utilizes a MySQL database to store encrypted passwords. It employs the MyISAM storage engine and avoids transaction logs to ensure data is deleted after a one-time view.

## Encryption Algorithm

Data stored in the database includes the Cipher text, encrypted with 256-bit AES in CBC mode using HMAC-SHA3-512 encryption. Encryption keys are not stored in the database or anywhere on the server, enhancing security.

## Memory Management

After creating a link, the system performs a full memory wipe and unsets all variables for good measure, ensuring data confidentiality.

## Usage Guide

Instructions for encrypting and sharing passwords, accessing shared passwords, and other functionalities provided by the service are available.

## Security Best Practices

Users are advised on creating strong passwords, securely sharing links, and handling sensitive information to maximize security.

## Contributing Guidelines

If you would like to contribute, reach out to @supertechguy

## License Information

The project is distributed under a GNU General Public license version 2, including terms and conditions for usage, modification, and distribution.

## Contact Information

For questions about the project, users can reach out to @supertechguy