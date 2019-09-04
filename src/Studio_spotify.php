<?php
/**
 *
 * Spotify OAuth2 light.
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

class Studio_spotify extends AbstractService
{
	/**
	 * Returns the user object of the requester's account.
	 *
	 * If the user-read-email scope is authorized, the returned JSON will include the email
	 * address that was entered when the user created their Spotify account.
	 * This email address is unverified; do not assume that Spotify
	 * has checked that email address actually belongs to the user.
	 *
	 * @see https://developer.spotify.com/documentation/general/guides/scopes/#user-read-email
	 */
	const SCOPE_USER_READ_EMAIL = 'user-read-email';

	/**
	 * Spotify constructor.
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
		if (empty($scopes))
		{
			/**
			 * You can specify multiple scopes by separating them with a space
			 * (implode the array with a space separator). See below.
			 */
			$scopes = [self::SCOPE_USER_READ_EMAIL];
		}

		parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

		if (null === $baseApiUri)
		{
			/**
			 * API version in use as today 04-09-2019
			 */
			$this->baseApiUri = new Uri('https://api.spotify.com/v1/');
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://accounts.spotify.com/authorize');
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://accounts.spotify.com/token');
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
			/* We are not sure if "$data['error']" might be an array */
			$message = is_array($data['error']) ? implode('<br>', $data['error']) : $data['error'];

			throw new TokenResponseException('Error in retrieving token: "' . $message . '"');
		}

		/**
		 * Spotify's token expires in 1 week (604800 seconds)
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
				'grant_type'		=> 'authorization_code',
				'response_type'		=> 'code',
				'redirect_uri'		=> $this->credentials->getCallbackUrl(),
			]
		);

		/**
		 * Scope is a list of OAuth2 scopes separated by url encoded spaces.
		 * Here the url will be encoded later by the logic, so use a normal space.
		 */
		$parameters['scope'] = implode(' ', $this->scopes);

		/**
		 * Whether or not to force the user to approve the app again if they’ve already done so.
		 * If false (default), a user who has already approved the application may be automatically
		 * redirected to the URI specified by redirect_uri.
		 * If true, the user will not be automatically redirected and will have to approve the app again.
		 *
		 * @see https://developer.spotify.com/documentation/general/guides/authorization-guide/#authorization-code-flow
		 */
		$parameters['show_dialog'] = 'false';

		/**
		 * Prevent CSRF and Clickjacking.
		 * That's not explicitly requested by Spotify.
		 *
		 * @see https://developer.spotify.com/documentation/general/guides/authorization-guide/#authorization-code-flow
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
