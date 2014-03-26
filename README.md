LDAP
====
This library is used to manage a directory via LDAP. It uses the DirectoryServices namespace and has primarily been used with an Active Directory domain. Brief list of features:

* Authenticate a user
* Get groups a user is a member of
* Get list of all groups in the directory
* Get list of all users in the directory
* Get certain properties of a user account

It also contains various maintenance methods to help manage a domain, things like getting a list of all users that have a certain attribute value blank, such as e-mail address or department. They are useful if you have web applications configured to use Windows authentication that rely on those kinds of properties, and you want to see which accounts need them set.
