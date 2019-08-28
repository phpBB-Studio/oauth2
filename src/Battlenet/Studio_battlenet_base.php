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
	const SCOPE_WOW_PROFILE		= 'wow.profile';
	const SCOPE_SC2_PROFILE		= 'sc2.profile';

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
		parent::__construct($credentials, $http_client, $storage, $scopes, $base_api_uri);

		if ($base_api_uri === null)
		{
			$this->baseApiUri = new Uri('https://' . $this->region . '.battle.net/');
		}
	}

	/**
	 * @return \OAuth\Common\Http\Uri\UriInterface
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://' . $this->region . '.battle.net/oauth/authorize');
	}

	/**
	 * @return \OAuth\Common\Http\Uri\UriInterface
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://' . $this->region . '.battle.net/oauth/token');
	}

	/**
	 * @param string $response_body
	 * @return \OAuth\Common\Token\TokenInterface|\OAuth\OAuth2\Token\StdOAuth2Token
	 * @throws \OAuth\Common\Http\Exception\TokenResponseException
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
			throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
		}

		$token = new StdOAuth2Token();

		$token->setAccessToken( $data['access_token'] );

		if (isset($data['expires_in']))
		{
			$token->setLifetime($data['expires_in']);
		}

		unset($data['access_token']);
		unset($data['expires_in']);

		$token->setExtraParams($data);

		return $token;
	}

	/**
	 * @return int
	 */
	protected function getAuthorizationMethod()
	{
		return static::AUTHORIZATION_METHOD_QUERY_STRING;
	}
}
