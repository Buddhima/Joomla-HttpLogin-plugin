<?php
defined( '_JEXEC' ) or die( 'Restricted access' );

/**
 * @version    2.5.0
 * @copyright  Copyright (C) 2013 Buddhima Wijeweera. All rights reserved.
 * @license    GNU/GPL
 * @autor      Buddhima Wijeweera
 * 
 *
*/

jimport('joomla.plugin.plugin');


class plgSystemHttplogin extends JPlugin
{

	function onAfterInitialise()
	{
		if ($this->params->get('authmethod','1')==='0') {
			$result = $this->basicAuthLogin();
		} else if ($this->params->get('authmethod','1')==='1'){
			$result = $this->encryptedLogin();
		}else if ($this->params->get('authmethod','1')==='2'){
			$result = $this->plainTextLogin();
		}

		return;
	}

	/**
	 * Login using basic http authentication
	 */
	function basicAuthLogin()
	{
		// Get the application object.
		$app = JFactory::getApplication();

		if(isset($_SERVER['PHP_AUTH_USER'])&&isset($_SERVER['PHP_AUTH_PW']))
		{
		// Get the log in credentials.
		$credentials = array();
		$credentials['username'] = $_SERVER['PHP_AUTH_USER'];
		$credentials['password'] = $_SERVER['PHP_AUTH_PW'];

		//if(!empty($credentials['username']) && !empty($credentials['password']))
		
			$options = array();
			$result = $app->login($credentials, $options);

			// if OK go to redirect page
			if ($this->params->get('redirect', null)) {
				if (!JError::isError($result)) {
					$app->redirect($this->params->get('redirect', null));
				}
			}
		}
		return;
	}

	/**
	 * Login using md5 hashed password+salt
	 * For internal usages (JFactory::getUser()->password)
	 */
	function encryptedLogin()
	{
		// Get the application object.
		$app = JFactory::getApplication();
		$input=$app->input;
		
		// Get all headers in HTTP request
		$headers=getallheaders();
				
		if(!empty($headers['Joomla-User']) && !empty($headers['Joomla-Password'])){
			
			// Filterout Jomla User Name and Joomla Password from headers
			$user=$headers['Joomla-User'];
			$password=$headers['Joomla-Password'];
			
			$db =& JFactory::getDbo();
			$query=$db->getQuery(true);
			$query->select(array('id', 'username', 'password'));
			$query->from('#__users');
			$query->where(array('username = '.$db->Quote( $user ), 'password = '.$db->Quote( $password )));
			
			$db->setQuery( $query );
			$result = $db->loadObject();

			if($result) {
				JPluginHelper::importPlugin('user');

				$options = array();
				$options['action'] = 'core.login.site';

				$response->username = $result->username;
				$result = $app->triggerEvent('onUserLogin', array((array)$response, $options));
			}

			// if OK go to redirect page
			if ($this->params->get('redirect')) {
				if ($result) {
					$app->redirect($this->params->get('redirect'));
				}
			}
		}
		return;
	}

	/**
	 * Login using password in plain text
	 */
	function plainTextLogin()
	{
		// Get the application object.
		$app = JFactory::getApplication();
		$input=$app->input;

		// Get the log in credentials.
		$credentials = array();
		$credentials['username'] = $input->get('user');
		$credentials['password'] = $input->get('password');

		if(!empty($credentials['username']) && !empty($credentials['password']))
		{

			$options = array();
			$result = $app->login($credentials, $options);

			// if OK go to redirect page
			if ($this->params->get('redirect', null)) {
				if (!JError::isError($result)) {
					$app->redirect($this->params->get('redirect', null));
				}
			}

		}

		return;
	}
	
	
}