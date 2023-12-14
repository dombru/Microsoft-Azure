<?php

namespace SocialiteProviders\Azure;

use Illuminate\Support\Arr;
use SocialiteProviders\Manager\OAuth2\User as oAuth2User;

class User extends oAuth2User
{
    /**
     * The user's principal name.
     *
     * @var string
     */
    public $principalName;

    /**
     * The user's mail.
     *
     * @var string
     */
    public $mail;

    /**
     * Get the principal name for the user.
     *
     * @return string
     */
    public function getPrincipalName()
    {
        return $this->principalName;
    }

    /**
     * Get the mail for the user.
     *
     * @return string
     */
    public function getMail()
    {
        return $this->mail;
    }

    public function mapExtraFields(array $user, array $mappings)
    {
        foreach ($mappings as $mapper) {
            list($key, $path) = explode(':', $mapper);
            $this->attributes[$key] = Arr::get($user, $path);
        }
    }
}
