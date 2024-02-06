
waamp server running php

look for `phpinfo.php` for all info

### Drupal
 Access the CHANGELOG.txt file on the server. The version information should be present in this file. 

**URL:** http://demo.ine.local/CHANGELOG.txt

By default, the CHANGELOG.txt is present in the drupal archive https://ftp.drupal.org/files/projects/drupal-{VERSION}.tar.gz. So, if the admin hasn't deleted the file, we can quickly identify the running CMS version.

Two modules available; drupalgeddon and drupalgeddon2

### WAMPSERVER and MySQL

>WampServer is a Windows web development environment. It allows you to create web applications with Apache2, PHP and a MySQL database. Alongside, PhpMyAdmin allows you to manage easily your databases

```bash
scanner/mysql/mysql_login
```
Brute force login module for MySQL DB

Otherwise if access is gained via other method, DB passwords can be found in `c:\wamp\www\wordpress\wp-config.php` or try searching with `dir /s $FILENAME`

Modify `phpmyadmin.conf` after gaining access from other method. Found in `wamp/alias` folrder. This will allow access to phpmyadmin if otherwise not available.

> download the `phpmyadmin.conf` file. Typically stored in the C drive in folder called `wamp`. File either in apps or `www`. This file is used to control access to `/phpmyadmin`

Edit this file to allow anyone to login `Allow from all` the reupload the file

to reflect changes restart server:
```cmd
net stop wampapache
```

```cmd
net start wampapache
```

Can access users and passwords inside phpmyadmin and wp_users

Once that's done head to `/wordpress/wp-admin` with either brute forced password or changed password.

