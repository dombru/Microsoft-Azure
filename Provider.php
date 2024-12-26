<?php

namespace SocialiteProviders\Azure;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'AZURE';

    /**
     * The base Azure Graph URL.
     *
     * @var string
     */
    protected $graphUrl = 'https://graph.microsoft.com/v1.0/me';

    /**
     * Default field list to request from Microsoft.
     *
     * @see https://docs.microsoft.com/en-us/graph/permissions-reference#user-permissions
     */
    protected const DEFAULT_FIELDS = ['id', 'displayName', 'businessPhones', 'givenName', 'jobTitle', 'mail', 'mobilePhone', 'officeLocation', 'preferredLanguage', 'surname', 'userPrincipalName'];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['User.Read'];

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->getBaseUrl().'/oauth2/v2.0/authorize', $state);
    }

    /**
     * Return the logout endpoint with an optional post_logout_redirect_uri query parameter.
     *
     * @param  string|null  $redirectUri  The URI to redirect to after logout, if provided.
     *                                    If not provided, no post_logout_redirect_uri parameter will be included.
     * @return string The logout endpoint URL.
     */
    public function getLogoutUrl(?string $redirectUri = null)
    {
        $logoutUrl = $this->getBaseUrl().'/oauth2/logout';

        return $redirectUri === null ?
            $logoutUrl :
            $logoutUrl.'?'.http_build_query(['post_logout_redirect_uri' => $redirectUri], '', '&', $this->encodingType);
    }

    protected function getTokenUrl(): string
    {
        return $this->getBaseUrl().'/oauth2/v2.0/token';
    }

    public function getAccessToken($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        $this->credentialsResponseBody = json_decode((string) $response->getBody(), true);

        return $this->parseAccessToken($response->getBody());
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $requestOptions = [
            RequestOptions::HEADERS => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
            RequestOptions::PROXY => $this->getConfig('proxy'),
        ];
        if ($this->getConfig('extra_fields', false)) {
            $requestOptions[RequestOptions::QUERY] = [
                '$select' => join(',', array_merge(self::DEFAULT_FIELDS, $this->getConfig('extra_fields', []))),
            ];
        }
        $response = $this->getHttpClient()->get($this->graphUrl, $requestOptions);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'            => $user['id'],
            'nickname'      => null,
            'name'          => $user['displayName'],
            'email'         => $user['userPrincipalName'],
            'principalName' => $user['userPrincipalName'],
            'mail'          => $user['mail'],
            'avatar'        => null,

            'businessPhones'    => Arr::get($user, 'businessPhones'),
            'displayName'       => Arr::get($user, 'displayName'),
            'givenName'         => Arr::get($user, 'givenName'),
            'jobTitle'          => Arr::get($user, 'jobTitle'),
            'mobilePhone'       => Arr::get($user, 'mobilePhone'),
            'officeLocation'    => Arr::get($user, 'officeLocation'),
            'preferredLanguage' => Arr::get($user, 'preferredLanguage'),
            'surname'           => Arr::get($user, 'surname'),
        ])->mapExtraFields($user, $this->getConfig('extra_mappings', []));
    }

    /**
     * Get the access token response for the given code.
     *
     * @param  string  $code
     * @return array
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS     => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
            RequestOptions::PROXY       => $this->getConfig('proxy'),
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * @return string
     */
    protected function getBaseUrl(): string
    {
        return 'https://login.microsoftonline.com/'.$this->getConfig('tenant', 'common');
    }

    public static function additionalConfigKeys(): array
    {
        return ['tenant', 'proxy', 'extra_fields', 'extra_mappings',
            'response_type', 'scopes', 'response_mode', 'use_nonce'];
    }

    protected function getCodeFields($state = null) : array
    {
        if($this->getConfig('scopes', false)) {
            $this->setScopes($this->getConfig('scopes'));
        }
        $fields = parent::getCodeFields($state);

        // adapt fields to ZHdK
        if($this->getConfig('response_type', false)) {
            $fields['response_type'] = $this->getConfig('response_type');
        }
        if($this->getConfig('response_mode', false)) {
            $fields['response_mode'] = $this->getConfig('response_mode');
        }
        if($this->getConfig('use_nonce', false)) {
            $fields['nonce'] = Str::random();
        }

        return $fields;
    }
}
