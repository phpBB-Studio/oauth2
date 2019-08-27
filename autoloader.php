<?php

// autoloader
spl_autoload_register(array(new phpbbstudio_autoloader(), 'autoload'));

if (!class_exists('Studio_github'))
{
	trigger_error('Autoloader not registered properly', E_USER_ERROR);
}

/**
 * Autoloader class
 *
 * @package Studio_github
 */
class phpbbstudio_autoloader
{
	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->path = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'src';
	}

	/**
	 * Autoloader
	 *
	 * @param string $class The name of the class to attempt to load.
	 */
	public function autoload($class)
	{
		// Only load the class if it starts with "SimplePie"
		if (strpos($class, 'Studio_github') !== 0)
		{
			return;
		}

		$filename = $this->path . DIRECTORY_SEPARATOR . str_replace('_', DIRECTORY_SEPARATOR, $class) . '.php';
		include $filename;
	}
}