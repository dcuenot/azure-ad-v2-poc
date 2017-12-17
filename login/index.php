<?php
session_start();
error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED);
ini_set('display_errors', 'On');

require_once ('config.php');
require_once ('functions.php');

if (!isset($_GET['code']) && !isset($_GET['scope'])) {
    echo '<form action="'.$_SERVER['PHP_SELF'].'" method="GET">
             <p>Scope : <input type="text" name="scope" value="openid Group.Read.All Mail.Read User.Read" size="40" /> (appli : openid / tablette : api://961d29f7-a93e-42f4-b923-b0b7d9c3615e/.default)</p>
             <p>Grant_type : <input type="text" name="grant_type" value="authorization_code" /> (appli : authorization_code / tablette : client_credentials)</p>
             <p><input type="submit" value="OK"></p>
            </form>';
    exit;
} elseif (!isset($_GET['code']) && isset($_GET['scope'])) {
    $_SESSION['scope'] = $_GET['scope'];
    $_SESSION['grant_type'] = $_GET['grant_type'];

    $params_authorize['scope'] = $_SESSION['scope'];
    $params_authorize['grant_type'] = $_SESSION['grant_type'];

    // Etape 1 : redirection pour se faire authentifier
    $authUrl = $url_authorize.'?'.queryParams($params_authorize);
    header('Location: '.$authUrl);
    exit;
} else {
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Titre de la page</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php

    $params_authorize["scope"] = $_SESSION['scope'];
    echo '<h2>Appel n°1 : Autorisation auprès du Portail Azure</h2>
        <strong>Url :</strong> '.$url_authorize.'<br/>
        <strong>Query Params</strong>';
        printParam(queryParams($params_authorize));

    echo '<h3>Réponse</h3>';
    echo '<pre>', json_encode($_GET, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';

    // Etape 2 : Après saisie du login / mdp sur le site d'Azure, récupération du code
    $state_returned = $_GET['state'];

    // Vérification du state, le state retourné doit être le même que le state envoyé
    if($state_returned != $params_authorize['state']) {
        exit('Fail state');
    }
    echo '<div class="w3-blue w3-padding w3-large"><i class="glyphicon glyphicon-question-sign"></i> A quoi correspond le session_state ?</div>
    <div class="w3-blue w3-padding w3-large"><i class="glyphicon glyphicon-question-sign"></i> Faut-il utiliser le nonce ?</div>';

    // Nonce non utilisé pour l'instant
    // A quoi sert le session state ?
    $session_state = $_GET['session_state'];

    // Injection du code récupéré après la requête 1
    $params_token['scope'] = $_SESSION['scope'];
    $params_token['grant_type'] = $_SESSION['grant_type'];
    $params_token['code'] = $_GET['code'];
    $json_token = appelToken($url_token, $params_token);

    echo '<h2>Appel n°2 : Les tokens d\'authentification</h2>
        <strong>Url :</strong> '.$url_token.'<br/>
        <strong>Post params</strong>';
    printParam(queryParams($params_token));

    echo '<h3>Réponse</h3>';
    echo '<pre>', json_encode($json_token, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';


    // Etape 3 : Récupération des clés => clés à stocker en cache dans le serveur
    $json_keys = keysToMap(appelKeys($url_keys));
    echo '<h2>Appel n°3 : Récupération de la clé publique</h2>
        <strong>Url :</strong> '.$url_keys.'<br/>
        <h3>Réponse simplifiée : kid => x5c</h3>
            <pre>', var_dump($json_keys), '</pre>';


    // Etape 4 : Affichage du contenu des tokens + Vérification de la signature
    echo '<h2>Affichage et vérification des clés</h2>';
    decodeJWT('Access Token', $json_token['access_token'], $json_keys);
    decodeJWT('Id Token', $json_token['id_token'], $json_keys);
    decodeJWT('Refresh Token', $json_token['refresh_token'], $json_keys);


    echo '<div class="w3-blue w3-padding w3-large"><i class="glyphicon glyphicon-question-sign"></i> A confirmer, mais si je comprends bien :
            <ul>
                <li>Il faut conserver l\'access_token au niveau de l\'appli cliente, et l\'utiliser pour obtenir les groupes</li>
                <li>Il faut véhiculer l\'id_token au sein de nos micro-services, et par conséquent, impossible (mais est-ce grave ?) de gérer les groupes côté microservices</li>
            </ul>
            <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens">Différences entre les tokens</a> - 
            <a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens#validating-tokens">Validation à faire sur les tokens JWT dans les microservices</a></div>';




    // Etape 5 : Appel des API Graph de Microsoft
    echo '<h2>Appel des API Graph</h2>';
    echo '<h3>Acces Token</h3>';
    apiWithBearer('https://graph.microsoft.com/v1.0/me/', $json_token['access_token']);
    apiWithBearer('https://graph.microsoft.com/v1.0/me/memberOf', $json_token['access_token']);
    apiWithBearer('https://login.microsoftonline.com/'.$tenant_id.'/openid/userinfo', $json_token['access_token']);

    echo '<h3>Id Token</h3>';
    apiWithBearer('https://graph.microsoft.com/v1.0/me/', $json_token['id_token']);
    apiWithBearer('https://graph.microsoft.com/v1.0/me/memberOf', $json_token['id_token']);
    apiWithBearer('https://login.microsoftonline.com/'.$tenant_id.'/openid/userinfo', $json_token['id_token']);

}

?>

</body>
</html>
