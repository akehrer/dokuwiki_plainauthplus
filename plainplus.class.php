<?php
/**
 * Plaintextplus authentication backend for dokuwiki that includes: 
 * - limit incorrect password entries before locking user out 
 * - set password expiration time limit
 * - set hard login session time limit
 * - track passwords and limit their reuse
 *
 * Based on the Plaintext authentication backend
 *
 * @author     Andreas Gohr <andi@splitbrain.org> (Plaintext)
 * @author     Chris Smith <chris@jalakai.co.uk> (Plaintext)
 * @author     Aaron Kehrer <akehrer@in2being.com> (Plaintextplus)
 */

class auth_plainplus extends auth_basic {

    // Security settings
	var $BadPassLimit = null; //The number of bad password attempts before the system locks out the user
	var $SessionTimeout = null; //Number of minutes of inactivity before the system requires re-login (mins)
	var $PasswordExpire = null; //Number of days after which current password expires (days)
	var $PasswordReuse = null; //Number of days after which an old password can be reused (days)
	
	// User information storage	
	var $UserDataDir = null;
	
	var $users = null;
    var $_pattern = array();

    /**
     * Constructor
     *
     * Carry out sanity checks to ensure the object is
     * able to operate. Set capabilities.
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     */
    function auth_plainplus() {
      global $config_cascade;
	  global $conf;

	  $this->BadPassLimit = $conf['auth']['plainplus']['bad_pass_limit'];
	  $this->SessionTimeout = $conf['auth']['plainplus']['session_timeout_min'] * 60; //mins to secs
	  $this->PasswordExpire = $conf['auth']['plainplus']['password_expire_days'] * 24 * 60 * 60; //days to secs
	  $this->PasswordReuse = $conf['auth']['plainplus']['password_reuse_days'] * 24 * 60 * 60; // days to secs
	  
	  $this->UserDataDir = DOKU_INC . '/auth/';

      if (!@is_readable($config_cascade['plainauth.users']['default'])){
        $this->success = false;
      }else{
        if(@is_writable($config_cascade['plainauth.users']['default'])){
          $this->cando['addUser']      = true;
          $this->cando['delUser']      = true;
          $this->cando['modLogin']     = true;
          $this->cando['modPass']      = true;
          $this->cando['modName']      = true;
          $this->cando['modMail']      = true;
          $this->cando['modGroups']    = true;
        }
        $this->cando['getUsers']     = true;
        $this->cando['getUserCount'] = true;
      }
    }

    /**
     * Check user+password [required auth function]
     *
     * Checks if the given user exists and the given
     * plaintext password is correct
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @return  bool
     */
    function checkPass($user,$pass){

	  $userinfo = $this->getUserData($user);
      if ($userinfo === false) return false;
		
	  $verify = auth_verifyPassword($pass,$this->users[$user]['pass']);
	  if($verify) {
	    $changes = array(
		  'badpass' => 0,
		  'newsession' => $this->SessionTimeout + time(),
		  'userip' => $_SERVER['REMOTE_ADDR'],
		);
		if($this->users[$user]['secu'][1] == 0)  {
			// if the passexpire value is 0 we assume this user existed before
			// plaintextplus was implemented and need to set the passexpire value
			$changes['pass'] = $pass;
		}
		$this->modifyUser($user,$changes);
		return true;
	  }
	  else {
	    $changes = array('badpass' => $this->users[$user]['secu'][0] + 1,);
		$this->modifyUser($user,$changes);
		return false;
	  }
    }
	
    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
	 * secu array   list of security items
	 *              (bad password, password expire, session expire, session IP)
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    function getUserData($user){
	  global $ACT;
	  global $INFO;

      if($this->users === null) $this->_loadUserData();
	  if($INFO['client'] == $user) {
	  // check security data and display messages if $user is the session user
		  if(intval($this->users[$user]['secu'][0]) > $this->BadPassLimit){
			msg("Bad password limit exceeded");
			$ACT = 'logout';
		  }
		  if(intval($this->users[$user]['secu'][1]) < time()){
			msg("The password for ".$user." has expired.  Please create a new one.");
			$ACT = 'profile';
		  }
	  }
	  
      return isset($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * Create a new User
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     */
    function createUser($user,$pwd,$name,$mail,$grps=null){
      global $conf;
      global $config_cascade;

      // user mustn't already exist
      if ($this->getUserData($user) !== false) return false;

      $pass = auth_cryptPassword($pwd);

      // set default group if no groups specified
      if (!is_array($grps)) $grps = array($conf['defaultgroup']);

      // prepare user line
	  // security contains
	  //	- Number of bad password attempts
	  //	- timestamp of when password expires
	  //	- timestamp of when login session timesout
	  //    - user's current session ip (null if logged out)
      $groups = join(',',$grps);
	  $security = join(',',array(0,time() + $this->PasswordExpire,time() + $this->SessionTimeout,null));
      $userline = join(':',array($user,$pass,$name,$mail,$groups,$security))."\n";
	  
      if (io_saveFile($config_cascade['plainauth.users']['default'],$userline,true)) {
        $this->users[$user] = compact('pass','name','mail','grps','secu');
        return $pwd;
      }

      msg('The '.$config_cascade['plainauth.users']['default'].
          ' file is not writable. Please inform the Wiki-Admin',-1);
      return null;
    }

    /**
     * Modify user data
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @param   $user      nick of the user to be changed
     * @param   $changes   array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    function modifyUser($user, $changes) {
      global $conf;
      global $ACT;
      global $INFO;
      global $config_cascade;

      // sanity checks, user must already exist and there must be something to change
      if (($userinfo = $this->getUserData($user)) === false) return false;
      if (!is_array($changes) || !count($changes)) return true;

      // update userinfo with new data, remembering to encrypt any password
      $newuser = $user;
	  $numbadpass = $userinfo['secu'][0];
	  $passexpire = $userinfo['secu'][1];
	  $sessiontimeout = $userinfo['secu'][2];
	  $userip = $userinfo['secu'][3];
      foreach ($changes as $field => $value) {
        if ($field == 'user') {
          $newuser = $value;
          continue;
        }
		if ($field == 'badpass') {
		  $numbadpass = $value;
		  continue;
		}
		if ($field == 'newsession') {
		  $sessiontimeout = $value;
		  continue;
		}
		if ($field == 'userip') {
			$userip = $value;
			continue;
		}
        if ($field == 'pass') {
		  $value = auth_cryptPassword($value);
		  if($this->checkUserPassList($user,$value) === false) {
			msg("Password reuse too soon!",-1);
			return false;
		  }
		  else {
			$numbadpass = 0;
			if ($ACT == 'resendpwd') {
			// if the password change came from a send new pass word action
			// make sure it expires now
				$passexpire = time();
			}
			else {
				$passexpire = time() + $this->PasswordExpire;
			}
			$passline = join(':',array(time(),$value))."\n";
			if (!io_saveFile($this->UserDataDir.$user.'.auth',$passline,true)) {
			  msg("Could not update the password list file.  Please contact administrator",-1);
			  return false;
			}
		  }
		}
        $userinfo[$field] = $value;
      }

      $groups = join(',',$userinfo['grps']);
	  $security = join(',',array($numbadpass,$passexpire,$sessiontimeout,$userip));
      $userline = join(':',array($newuser, $userinfo['pass'], $userinfo['name'], $userinfo['mail'], $groups, $security))."\n";

      if (!$this->deleteUsers(array($user))) {
        msg('Unable to modify user data. Please inform the Wiki-Admin',-1);
        return false;
      }

      if (!io_saveFile($config_cascade['plainauth.users']['default'],$userline,true)) {
        msg('There was an error modifying your user data. You should register again.',-1);
        // FIXME, user has been deleted but not recreated, should force a logout and redirect to login page
        $ACT == 'register';
        return false;
      }

      $this->users[$newuser] = $userinfo;
      return true;
    }

    /**
     *  Remove one or more users from the list of registered users
     *
     *  @author  Christopher Smith <chris@jalakai.co.uk>
     *  @param   array  $users   array of users to be deleted
     *  @return  int             the number of users deleted
     */
    function deleteUsers($users) {
      global $config_cascade;

      if (!is_array($users) || empty($users)) return 0;

      if ($this->users === null) $this->_loadUserData();

      $deleted = array();
      foreach ($users as $user) {
        if (isset($this->users[$user])) $deleted[] = preg_quote($user,'/');
      }

      if (empty($deleted)) return 0;

      $pattern = '/^('.join('|',$deleted).'):/';

      if (io_deleteFromFile($config_cascade['plainauth.users']['default'],$pattern,true)) {
        foreach ($deleted as $user) unset($this->users[$user]);
        return count($deleted);
      }

      // problem deleting, reload the user list and count the difference
      $count = count($this->users);
      $this->_loadUserData();
      $count -= count($this->users);
      return $count;
    }

    /**
     * Return a count of the number of user which meet $filter criteria
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     */
    function getUserCount($filter=array()) {

      if($this->users === null) $this->_loadUserData();

      if (!count($filter)) return count($this->users);

      $count = 0;
      $this->_constructPattern($filter);

      foreach ($this->users as $user => $info) {
          $count += $this->_filter($user, $info);
      }

      return $count;
    }

    /**
     * Bulk retrieval of user data
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @param   start     index of first user to be returned
     * @param   limit     max number of users to be returned
     * @param   filter    array of field/pattern pairs
     * @return  array of userinfo (refer getUserData for internal userinfo details)
     */
    function retrieveUsers($start=0,$limit=0,$filter=array()) {

      if ($this->users === null) $this->_loadUserData();

      ksort($this->users);

      $i = 0;
      $count = 0;
      $out = array();
      $this->_constructPattern($filter);

      foreach ($this->users as $user => $info) {
        if ($this->_filter($user, $info)) {
          if ($i >= $start) {
            $out[$user] = $info;
            $count++;
            if (($limit > 0) && ($count >= $limit)) break;
          }
          $i++;
        }
      }

      return $out;
    }

    /**
     * Only valid pageid's (no namespaces) for usernames
     */
    function cleanUser($user){
        global $conf;
        return cleanID(str_replace(':',$conf['sepchar'],$user));
    }

    /**
     * Only valid pageid's (no namespaces) for groupnames
     */
    function cleanGroup($group){
        global $conf;
        return cleanID(str_replace(':',$conf['sepchar'],$group));
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    function _loadUserData(){
      global $config_cascade;

      $this->users = array();

      if(!@file_exists($config_cascade['plainauth.users']['default'])) return;

      $lines = file($config_cascade['plainauth.users']['default']);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if(empty($line)) continue;

        $row    = explode(":",$line,6);
        $groups = array_values(array_filter(explode(",",$row[4])));
		$security = array_values(explode(",",$row[5]));

        $this->users[$row[0]]['pass'] = $row[1];
        $this->users[$row[0]]['name'] = urldecode($row[2]);
        $this->users[$row[0]]['mail'] = $row[3];
        $this->users[$row[0]]['grps'] = $groups;
		$this->users[$row[0]]['secu'] = $security;
		
      }
    }

    /**
     * return 1 if $user + $info match $filter criteria, 0 otherwise
     *
     * @author   Chris Smith <chris@jalakai.co.uk>
     */
    function _filter($user, $info) {
        // FIXME
        foreach ($this->_pattern as $item => $pattern) {
            if ($item == 'user') {
                if (!preg_match($pattern, $user)) return 0;
            } else if ($item == 'grps') {
                if (!count(preg_grep($pattern, $info['grps']))) return 0;
            } else {
                if (!preg_match($pattern, $info[$item])) return 0;
            }
        }
        return 1;
    }

    function _constructPattern($filter) {
      $this->_pattern = array();
      foreach ($filter as $item => $pattern) {
//        $this->_pattern[$item] = '/'.preg_quote($pattern,"/").'/i';          // don't allow regex characters
        $this->_pattern[$item] = '/'.str_replace('/','\/',$pattern).'/i';    // allow regex characters
      }
    }
	function useSessionCache($user){
      global $conf;
	  global $ACT;
	  
	  if (($userinfo = $this->getUserData($user)) === false) return false;
	  $badpass = intval($userinfo['secu'][0]);
	  $passexpire = intval($userinfo['secu'][1]);
	  $sessiontimeout = intval($userinfo['secu'][2]);
	  
	  if(time() >= $sessiontimeout){
		msg("Your session has expired.  Please log in.");
		$ACT = logout;
		return false;
	  }
	  else {
		//** SOME DEBUGGING CODE TO CHECK VALUES **
		//msg("The time now is:  ".strftime($conf['dformat'],time()));
		//msg("Your session will expire on: ".strftime($conf['dformat'],$sessiontimeout));
		//msg("Your password will expire on: ".strftime($conf['dformat'],$passexpire));
		//msg("Total bad password attempts: ".$badpass);
		$changes = array(
		  'badpass' => 0,
		  'newsession' => $this->SessionTimeout + time(),
		);
		$this->modifyUser($user,$changes);
	  }
	  
      return ($_SESSION[DOKU_COOKIE]['auth']['time'] >= @filemtime($conf['cachedir'].'/sessionpurge'));
	}
	
	/**
	 * Check a user's list of old passwords and disallow 
	 * reuse of passwords with in $PasswordReuse
	 *
	 * returns false if password cannot be used
	 **/
	function checkUserPassList($user,$hashpass){
		$this->passwords = array();
		if(!@file_exists($this->UserDataDir.$user.'.auth')) return;

		$lines = file($this->UserDataDir.$user.'.auth');
		foreach($lines as $line){
			$line = trim($line);
			if(empty($line)) continue;

			$row = explode(":",$line,2);
			
			if(time() - $row[0] > $this->PasswordReuse) continue;
			if($row[1] == $hashpass) return false;			
		}
		return true;
	}
}

//Setup VIM: ex: et ts=2 :
