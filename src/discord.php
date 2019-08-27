<?php
/**
 *
 * Discord OAuth2 light.
 * A class for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, phpBB Studio, https://www.phpbbstudio.com
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class discord extends AbstractService
{
	/**
	 * discord constructor.
	 *
	 * @param \OAuth\Common\Consumer\CredentialsInterface	$credentials
	 * @param \OAuth\Common\Http\Client\ClientInterface		$httpClient
	 * @param \OAuth\Common\Storage\TokenStorageInterface	$storage
	 * @param array											$scopes
	 * @param \OAuth\Common\Http\Uri\UriInterface|null		$baseApiUri
	 */
	public function __construct(
		CredentialsInterface $credentials,
		ClientInterface $httpClient,
		TokenStorageInterface $storage,
		$scopes = [],
		UriInterface $baseApiUri = null
	)
	{
		parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

		if (null === $baseApiUri)
		{
			/**
			 * Omitting the version number from the route will route
			 * requests to the current default version. (v6 as of 24-08-2019)
			 *
			 * @see https://discordapp.com/developers/docs/reference#api-versioning
			 */
			$this->baseApiUri = new Uri('https://discordapp.com/api/');
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://discordapp.com/api/oauth2/authorize');
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://discordapp.com/api/oauth2/token');
	}

	/**
	 * {@inheritdoc}
	 */
	protected function getAuthorizationMethod()
	{
		return static::AUTHORIZATION_METHOD_HEADER_BEARER;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function parseAccessTokenResponse($responseBody)
	{
		$data = json_decode($responseBody, true);

		if (null === $data || !is_array($data))
		{
			throw new TokenResponseException('Unable to parse response.');
		}
		else if (isset($data['error']))
		{
			throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
		}

		/**
		 * Discord's token expires in 1 week (604800 seconds)
		 * Let the logic discover it itself though.
		 */
		$token = new StdOAuth2Token();

		$token->setAccessToken($data['access_token']);

		if (isset($data['expires_in']))
		{
			$token->setLifetime($data['expires_in']);

			unset($data['expires_in']);
		}

		if (isset($data['refresh_token']))
		{
			$token->setRefreshToken($data['refresh_token']);

			unset($data['refresh_token']);
		}

		unset($data['access_token']);

		$token->setExtraParams($data);

		return $token;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationUri(array $additionalParameters = [])
	{
		$parameters = array_merge(
			$additionalParameters,
			[
				'client_id'			=> $this->credentials->getConsumerId(),

				/** @see https://discordapp.com/developers/docs/topics/oauth2#authorization-code-grant */
				'grant_type'		=> 'authorization_code',
				'response_type'		=> 'code',
				'redirect_uri'		=> $this->credentials->getCallbackUrl(),
				'scope'				=> 'identify',
			]
		);

		/**
		 * If the user has previously authorized our application
		 * then skip the authorization screen and redirect it back to us.
		 */
		$parameters['prompt'] = 'none';

		/**
		 * Prevent CSRF and Clickjacking.
		 * That's not explicitly requested by Discord.
		 *
		 * @see https://discordapp.com/developers/docs/topics/oauth2#state-and-security
		 */
		$parameters['state'] = $this->generateAuthorizationState();

		/* Store the generated state */
		$this->storeAuthorizationState($parameters['state']);

		/* Build the url */
		$url = clone $this->getAuthorizationEndpoint();

		foreach ($parameters as $key => $val)
		{
			$url->addToQuery($key, $val);
		}

		return $url;
	}
}
