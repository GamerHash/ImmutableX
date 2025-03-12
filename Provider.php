<?php

namespace SocialiteProviders\ImmutableX;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    protected $scopes = ['openid', 'email', 'offline_access', 'transact'];

    protected $stateless = true;

    protected $usesPKCE = true;

    protected $scopeSeparator = ' ';

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://auth.immutable.com/oauth/authorize',
            $state
        );
    }

    /**
     * Get the token URL to exchange an authorization code for an access token.
     */
    protected function getTokenUrl()
    {
        return 'https://auth.immutable.com/oauth/token';
    }

    /**
     * Retrieve the user’s information using the access token.
     */
    public function getUserByToken($token)
    {
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
        ])->get('https://auth.immutable.com/userinfo')->getBody();


        return json_decode($response, true);
    }

    /**
     * Map Immutable X user object to Socialite User.
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => null,
            'name' => null,
            'email' => $user['email'] ?? null,
            'avatar' => null,
            'email_verified' => $user['email_verified'] ?? false,
            'passport' => json_decode(json_encode($user['passport']), true) ?? [],
        ]);
    }

    public function getAccessTokenResponse($code)
    {
        $fields = Arr::except($this->getTokenFields($code), ['client_secret']);

        $response = Http::asForm()->post($this->getTokenUrl(), $fields);

        return json_decode($response->getBody(), true);
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        if (empty($response['id_token'])) {
            throw new \Exception("ID Token is missing from the response.");
        }

        $this->credentialsResponseBody = $response;

        $user = $this->decodeIdToken($response['id_token']);

        $token = $this->parseAccessToken($response);

        $this->user = $this->mapUserToObject($user);

        if ($this->user instanceof User) {
            $this->user->setAccessTokenResponseBody($this->credentialsResponseBody);
        }

        return $this->user->setToken($token)
            ->setRefreshToken($this->parseRefreshToken($response))
            ->setExpiresIn($this->parseExpiresIn($response))
            ->setApprovedScopes($this->parseApprovedScopes($response));
    }

    /**
     * Decode and validate ID Token.
     */
    public function decodeIdToken($idToken)
    {
        try {
            // Fetch ImmutableX public keys
            $keysResponse = $this->getHttpClient()->get('https://auth.immutable.com/.well-known/jwks.json');
            $keys = json_decode($keysResponse->getBody(), true);

            if (empty($keys['keys'])) {
                throw new \Exception("Failed to fetch ImmutableX public keys.");
            }

            // Decode and verify the ID Token
            $decoded = JWT::decode($idToken, JWK::parseKeySet($keys));

            return (array)$decoded;
        } catch (\Exception $e) {
            throw new \Exception("Invalid ID Token: " . $e->getMessage());
        }
    }
}
