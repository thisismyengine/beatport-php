<?php

namespace Beatport;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack as GuzzleHandler;
use GuzzleHttp\Subscriber\Oauth\Oauth1;
use Psr\Http\Message\StreamInterface;

class Client
{
    const OAUTH_URI = 'https://oauth-api.beatport.com';

    /**
     * @var GuzzleHttp\Client
     */
    private $client;

    public function __construct($params)
    {
        // assign beatport credentials
        $consumer_key = $params['consumer'];
        $consumer_secret = $params['secret'];
        
        $username = $params['username'];
        $password = $params['password'];

        // authenticate call
        $this->client = $this->oAuth_authenticate($consumer_key, $consumer_secret, $username, $password);
    }

    /**
     * Handle Beatport's 3-legged authentication process.
     *
     * @param string $consumer_key    Beatport consumer key
     * @param string $consumer_secret Beatport consumer secret
     * @param string $username       Beatport username
     * @param string $password       Beatport password
     *
     * @return GuzzleHttp\Client Fully authenticated Guzzle client   
     */
    private function oAuth_authenticate($consumer_key, $consumer_secret, $username, $password)
    {
        $result = [];

        // first leg

        // create oauth instance
        $oauth = new Oauth1([
            'consumer_key' => $consumer_key,
            'consumer_secret' => $consumer_secret,
            'token_secret' => '',
        ]);

        // push oauth to guzzle middleware stack
        $stack = $this->create_stack($oauth);

        // set up http client and pass guzzle stack
        $client = new GuzzleClient(['base_uri' => self::OAUTH_URI, 'auth' => 'oauth', 'handler' => &$stack]);

        // request the token without redirect
        $response = $client->post('identity/1/oauth/request-token', [
            'form_params' => [
                'oauth_callback' => 'oob',
            ],
        ]);

        // parse first leg response
        $result[] = $this->parse_response($response->getBody());

        // second leg

        // prepare post arguments
        $post_args = [
            'oauth_token' => $result[0]['oauth_token'],
            'username' => $username,
            'password' => $password,
            'submit' => 'Login',
        ];

        // submit credentials
        $response = $client->post('identity/1/oauth/authorize-submit', [
            'form_params' => $post_args,
        ]);

        // parse second leg response
        $result[] = $this->parse_response($response->getBody());

        // third leg

        // create new oauth with tokens
        $oauth = new Oauth1([
            'consumer_key' => $consumer_key,
            'consumer_secret' => $consumer_secret,
            'token' => $result[1]['oauth_token'],
            'token_secret' => $result[0]['oauth_token_secret'],
        ]);

        // push second oauth to guzzle middleware stack
        $stack = $this->create_stack($oauth);

        // send off for final access token
        $response = $client->post('identity/1/oauth/access-token', [
            'form_params' => [
                'oauth_verifier' => $result[1]['oauth_verifier'],
            ],
        ]);

        // parse third leg response
        $result[] = $this->parse_response($response->getBody());

        // create final oauth object so we can use it on subsequent calls
        $oauth = new Oauth1([
            'consumer_key' => $consumer_key,
            'consumer_secret' => $consumer_secret,
            'token' => $result[2]['oauth_token'],
            'token_secret' => $result[2]['oauth_token_secret'],
        ]);

        $stack = $this->create_stack($oauth);

        return $client;
    }

    /**
     * Process API request.
     *
     * @param array $parameters API filters
     *
     * @return string Response
     */
    public function get($parameters)
    {
        // parameters array with facets, sortBy, perPage, id, url, etc
        $method = $parameters['method']; // this is the API method, e.g. tracks, releases etc
        unset($parameters['method']); // unset it as it's not a query param

        // make the api call
        $response = $this->client->get('catalog/3/'.$method, [
            'query' => $parameters
        ]);

        // get the response
        $json = $response->getBody();

        // return an array
        return json_decode($json, true);
    }

    /**
     * Parse Beatport response body and put it into an array.
     *
     * @param Psr\Http\Message\StreamInterface $body
     *
     * @return array Decoded stream body
     */
    private function parse_response(StreamInterface $body)
    {
        $params = urldecode((string) $body);
        $result = [];
        parse_str($params, $result);

        return $result;
    }

    /**
     * Stack middleware on top of Guzzle's HTTP handler function.
     *
     * @param GuzzleHttp\Subscriber\Oauth\Oauth1 $oauth OAuth 1
     *
     * @return GuzzleHttp\HandlerStack Guzzle middleware stack
     */
    private function create_stack($oauth)
    {
        // create guzzle middleware
        $stack = GuzzleHandler::create();
        $stack->push($oauth);

        return $stack;
    }
}
