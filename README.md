# passwd.trade

passwd.trade is a self-destructing secure password transfer service.

## Technologies Used

The project runs on Apache, PHP, and MySQL.

## Database Management

passwd.trade utilizes a MySQL database to store encrypted passwords. It employs the MyISAM storage engine and avoids transaction logs to ensure data is deleted after a one-time view.

## Encryption Algorithm

Data stored in the database includes the Cipher text, encrypted with 256-bit AES in CBC mode using HMAC-SHA3-512 encryption. Encryption keys are not stored in the database or anywhere on the server, enhancing security.

## Memory Management

After creating a link, the system overwrites the variables with nulls and then releases the memory, ensuring data confidentiality.

## Usage Guide

Enter the password in the text area to be encrypted, click "Generate Link".  Copy the link provided and send the link to the recipient.  When the recipient recieves and clicks on the link, the password will be displayed and the data in the database will be destroyed.  Thereby preventing others from obtaining the password using the same link.

## Security Best Practices

Users are advised on creating strong passwords, securely sharing links, and handling sensitive information to maximize security.

## Contributing Guidelines

If you would like to contribute, reach out to @supertechguy

## License Information

The project is distributed under a GNU General Public license version 2, including terms and conditions for usage, modification, and distribution.

## Contact Information

For questions about the project, users can reach out to @supertechguy
