<?php
// configuration for the plainplus authentication system
$conf['auth']['plainplus']['bad_pass_limit'] = 5; //The number of bad password attempts before the system locks out the user
$conf['auth']['plainplus']['session_timeout_min'] = 15; //Number of minutes of inactivity before the system requires re-login (mins)
$conf['auth']['plainplus']['password_expire_days'] = 90; //Number of days after which current password expires (days)
$conf['auth']['plainplus']['password_reuse_days'] = 365; //Number of days after which an old password can be reused (days)
?>