<?php
/**
 *
 * phpBB Studio - GitHub OAuth2 light.
 * A class for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, phpBB Studio, https://www.phpbbstudio.com
 * @license MIT
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

class Studio_github extends AbstractService
{
	/**
	 * Grants read-only access to public information
	 * (includes public user profile info, public repository info, and gists)
	 *
	 * @see https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/#available-scopes
	 */
	const SCOPE_READONLY = '';

	/**
	 * Studio Github constructor.
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
			$scopes = [self::SCOPE_READONLY];
		}

		parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

		if (null === $baseApiUri)
		{
			$this->baseApiUri = new Uri('https://api.github.com/');
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://github.com/login/oauth/authorize');
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://github.com/login/oauth/access_token');
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
	protected function getExtraOAuthHeaders()
	{
		return array('Accept' => 'application/json');
	}

	/**
	 * {@inheritdoc}
	 */
	protected function getExtraApiHeaders()
	{
		/** @see https://developer.github.com/v3/media/#request-specific-version */
		return array('Accept: application/vnd.github.v3+json');
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
		 * GitHubs's token never expires because it does
		 * return a negative value and the refresh is null.
		 *
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
				'redirect_uri'		=> $this->credentials->getCallbackUrl(),
			]
		);

		/**
		 * Scope is a list of OAuth2 scopes separated by url encoded spaces.
		 * Here the url will be encoded later by the logic, so use a normal space.
		 */
		$parameters['scope'] = implode(' ', $this->scopes);

		/**
		 * Prevent CSRF and Clickjacking.
		 * That's not explicitly requested by GitHub.
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
