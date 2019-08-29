<?php
/**
 *
 * phpBB Studio - Battle.net OAuth2 light. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2019, phpBB Studio, https://www.phpbbstudio.com
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Studio_battlenet_base extends AbstractService
{
	/**
	 * Returns the user Blizzard Account ID and BattleTag
	 * (For OAuth2, this requires the identify scope)
	 *
	 * @see https://develop.battle.net/documentation/guides/using-oauth/authorization-code-flow
	 */
	const SCOPE_ACCOUNT_PUBLIC = 'account.public';

	/**
	 * BattleNet Region
	 *
	 * @var string region
	 */
	protected $region;

	public function __construct(
		Credentials $credentials,
		ClientInterface $http_client,
		TokenStorageInterface $storage,
		$scopes = [],
		UriInterface $base_api_uri = null
	)
	{
		if (empty($scopes))
		{
			/**
			 * You can specify multiple scopes by separating them with a space
			 * (implode the array with a space separator). See below.
			 */
			$scopes = [self::SCOPE_ACCOUNT_PUBLIC];
		}

		parent::__construct($credentials, $http_client, $storage, $scopes, $base_api_uri);

		if ($base_api_uri === null)
		{
			$this->baseApiUri = new Uri('https://' . $this->region . '.battle.net/');
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://' . $this->region . '.battle.net/oauth/authorize');
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://' . $this->region . '.battle.net/oauth/token');
	}

	/**
	 * {@inheritdoc}
	 */
	protected function getAuthorizationMethod()
	{
		return static::AUTHORIZATION_METHOD_QUERY_STRING;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function parseAccessTokenResponse($response_body)
	{
		$data = json_decode( $response_body, true );

		if ($data === null || !is_array($data))
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
		 * Blizzard access tokens last for 24 hours.
		 * A user changing their password, removing the authorization for an application's
		 * account, or getting their account locked for any reason, results in the expiration of their current access tokens.
		 * Developers should always check the response and request a new access token if the current one fails to work.
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
				'response_type'		=> 'code',
				'grant_type'		=> 'authorization_code',
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
		 * That's not explicitly requested by .
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
