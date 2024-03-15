# passwd.trade

passwd.trade is a self destructing secure password transfer service.

The project runs on Apache / PHP / MySQL

It allows the data to be view one time, before it is deleted from the MySQL MyISAM Database.  MyISAM was used to avoid transaction logs.

The data stored in the database includes the Cipher text, which is encrypted with 256-bit AES in CBC mode using HMAC-SHA3-512 encryption, an ID and a authentication code.

The authentication code is used to verify access to the cipher text and the ID is used to locate it in the database.  But the encryption keys to decrypt it are not stored in the database or anywhere on the server, and are only available in the link that is distributed to the user.

For questions about the project reach out to me.

--supertechguy