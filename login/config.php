<?php

// Common parameters
$tenant_id = '';
$client_id = '';
$client_secret = '';
//$scope = "openid";
//$grant_type = "authorization_code";

// scope pour parler entre tablette et backend
//$scope = "api://961d29f7-a93e-42f4-b923-b0b7d9c3615e/.default";
//$grant_type = "client_credentials";

// Paramètres pour l'appel de l'API authorize
$url_authorize = 'https://login.microsoftonline.com/'.$tenant_id.'/oauth2/v2.0/authorize';
$params_authorize = array(
    "client_id" => $client_id,
    "response_type" => "code",
    "redirect_url" => "http://locahost:9191/login",
    "response_mode" => "query",
    "scope" => $scope,
    "state" => "12345");

$url_token = 'https://login.microsoftonline.com/'.$tenant_id.'/oauth2/v2.0/token';
$params_token = array(
    "grant_type" => $grant_type,
    "client_id" => $client_id,
    "redirect_url" => 'http://localhost:9191/login',
    "scope" => $scope,
    "code" => '',
    "client_secret" => $client_secret
);

$url_keys = 'https://login.microsoftonline.com/'.$tenant_id.'/discovery/keys';

// Url pour avoir tous les endpoints
$urlConfig = 'https://login.microsoftonline.com/'.$tenant_id.'/.well-known/openid-configuration';
