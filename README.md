#Welcome to passwd.trade

Welcome to passwd.trade, a secure password transfer service designed to self-destruct after a single use.

#What Technologies Do We Use?

We use Apache, PHP, and MySQL to power this project.

#How Do We Manage the Database?

Our system relies on a MySQL database. We use the MyISAM storage engine and avoid transaction logs to ensure that data is deleted after it's been viewed once.

#How Do We Keep Your Data Safe?

We encrypt your passwords using 256-bit AES in CBC mode with HMAC-SHA3-512 encryption. We never store encryption keys in the database or on the server, which adds an extra layer of security.

#How Do We Handle Memory?

Once a link is generated, we overwrite the variables with nulls and release the memory to keep your data confidential.

#How Do You Use It?

1. Enter your password in the text area.
2. Click "Generate Link".
3. Copy the link provided and send it to your recipient.
4. When your recipient clicks on the link, they'll see the password, and the data in our database will be destroyed, preventing anyone else from accessing it.

#How Can You Keep Your Data Secure?

We encourage users to create strong passwords, share links securely, and handle sensitive information with care to maximize security.

#How Can You Contribute?

If you'd like to contribute to this project, please reach out to @supertechguy.

#What Are the Licensing Terms?

This project is distributed under the GNU General Public License version 2, which outlines terms and conditions for usage, modification, and distribution.

#Need Help?

If you have any questions about the project, feel free to contact @supertechguy.
