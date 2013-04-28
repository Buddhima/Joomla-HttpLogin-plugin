<?php

/**
 * @version    1.0.0
 * @copyright  Copyright (C) 2013 Buddhima Wijeweera. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 * @autor      Buddhima Wijeweera
 *
 *
 */

defined('_JEXEC') or die('Restricted access');


/**
 * Plugin for bypass login window in Joomla - Both front-end and back-end
 *  
 * 
 */
class plgSystemHttplogin extends JPlugin
{

	/**
	 * Activated after Initialise method in the execution cycle
	 */
	function onAfterInitialise()
	{
		if ($this->params->get('authmethod', '1') === '0')
		{
			$result = $this->basicAuthLogin();
		}
		elseif ($this->params->get('authmethod', '1') === '1')
		{
			$result = $this->encryptedLogin();
		}
		elseif ($this->params->get('authmethod', '1') === '2')
		{
			$result = $this->plainTextLogin();
		}
		elseif ($this->params->get('authmethod', '1') === '3')
		{
			$result = $this->basicAuthEncryptedLogin();
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

		if (isset($_SERVER['PHP_AUTH_USER'])&&isset($_SERVER['PHP_AUTH_PW']))
		{
			// Get the log in credentials.
			$credentials = array();
			$credentials['username'] = $_SERVER['PHP_AUTH_USER'];
			$credentials['password'] = $_SERVER['PHP_AUTH_PW'];

			try
			{

				$options = array();
				$result = $app->login($credentials, $options);

				// If OK go to redirect page
				if ($this->params->get('redirect', null))
				{
					$app->redirect($this->params->get('redirect', null));
				}
			}
			catch (Exception $e)
			{
				echo 'Error: ' . $e->getMessage();
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
		$input = $app->input;

		// Get all headers in HTTP request - under Apache
		$headers = getallheaders();

		if (!empty($headers['Joomla-User']) && !empty($headers['Joomla-Password']))
		{

			// Filterout Jomla User Name and Joomla Password from headers
			$user = $headers['Joomla-User'];
			$password = $headers['Joomla-Password'];

			$db = JFactory::getDbo();
			$query = $db->getQuery(true);
			$query->select(array('id', 'username', 'password'));
			$query->from('#__users');
			$query->where(array('username = ' . $db->Quote($user), 'password = ' . $db->Quote($password)));

			$db->setQuery($query);
			$result = $db->loadObject();

			if ($result)
			{
				JPluginHelper::importPlugin('user');

				$options = array();
				$options['action'] = 'core.login.site';

				$response->username = $result->username;
				$result = $app->triggerEvent('onUserLogin', array((array) $response, $options));
			}

			// If OK go to redirect page
			if ($this->params->get('redirect'))
			{
				if ($result)
				{
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
		$input = $app->input;

		// Get the log in credentials.
		$credentials = array();
		$credentials['username'] = $input->get('user');
		$credentials['password'] = $input->get('password');

		if (!empty($credentials['username']) && !empty($credentials['password']))
		{
			try
			{
				$options = array();
				$result = $app->login($credentials, $options);

				// If OK go to redirect page
				if ($this->params->get('redirect', null))
				{
					if (!JError::isError($result))
					{
						$app->redirect($this->params->get('redirect', null));
					}
				}
			}
			catch (Exception $e)
			{
				echo 'Error: ' . $e->getMessage();
			}

		}

		return;
	}
	
	/**
	 * Login using md5 hashed password+salt through Basic HTTP Authentication
	 * For internal usages (JFactory::getUser()->password , will return hashed_password_with_salt)
	 * Then base64_encode (user_name : hashed_password_with_salt)
	 */
	function basicAuthEncryptedLogin()
	{
		// Get the application object.
		$app = JFactory::getApplication();

		if (!empty($_SERVER['PHP_AUTH_USER'])&&isset($_SERVER['PHP_AUTH_PW']))
		{

			// Filterout Jomla User Name and Joomla Password from headers
			$user = $_SERVER['PHP_AUTH_USER'];
			$password = $_SERVER['PHP_AUTH_PW'];

			$db = JFactory::getDbo();
			$query = $db->getQuery(true);
			$query->select(array('id', 'username', 'password'));
			$query->from('#__users');
			$query->where(array('username = ' . $db->Quote($user), 'password = ' . $db->Quote($password)));

			$db->setQuery($query);
			$result = $db->loadObject();

			if ($result)
			{
				JPluginHelper::importPlugin('user');

				$options = array();
				$options['action'] = 'core.login.site';

				$response->username = $result->username;
				$result = $app->triggerEvent('onUserLogin', array((array) $response, $options));
			}

			// If OK go to redirect page
			if ($this->params->get('redirect'))
			{
				if ($result)
				{
					$app->redirect($this->params->get('redirect'));
				}
			}
		}
		return;
	}

}
