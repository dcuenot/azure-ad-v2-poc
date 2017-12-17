<?php

function decodeJWT($name, $jwt, $keys) {
    echo '<h3>'.$name.'</h3>';
    if(is_null($jwt)) {
        echo '<pre>Token vide...</pre>';
        return;
    }

    $ret = [];
    list($header, $payload, $signature) = explode('.', $jwt);

    $ret['header'] = json_decode(base64_decode($header), true);
    $ret['payload'] = json_decode(base64_decode($payload), true);
    $decoded_signature = base64_decode(strtr($signature, '-_', '+/'));

    if(is_null($ret['header'])) {
        echo '<pre>Ce token n\'est pas un JWT</pre>';
        return;
    }

    echo '<h4 class="header">Header</h4>';
    echo '<pre>', json_encode($ret['header'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';
    echo '<h4 class="payload">Payload</h4>';
    echo '<pre>', json_encode($ret['payload'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';

    $public_cert = "-----BEGIN CERTIFICATE-----\n".$keys[$ret['header']['kid']]."\n-----END CERTIFICATE-----";
    $ok = openssl_verify($header.'.'.$payload, $decoded_signature, $public_cert , OPENSSL_ALGO_SHA256);

    if ($ok == 1) {
        echo '<div class="w3-teal w3-padding w3-large "><i class="glyphicon glyphicon-ok-sign"></i> Signature validée</div>';
    } elseif ($ok == 0) {
        echo '<div class="w3-red w3-padding w3-large"><i class="glyphicon glyphicon-remove-sign"></i> Signature erronée</div>';
    } else {
        echo '<div class="w3-red w3-padding w3-large"><i class="glyphicon glyphicon-remove-sign"></i> Erreur</div>';
    }

    return $ret;
}

function apiWithBearer($url, $bearer_token) {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    $request_headers = array();
    $request_headers[] = 'Accept: application/json';
    $request_headers[] = 'Authorization: Bearer '. $bearer_token;
    curl_setopt($ch, CURLOPT_HTTPHEADER, $request_headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);

    echo '  <strong>Url :</strong> '.$url.'<br/>
            <strong>Header :</strong><br/><pre>', json_encode($request_headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>
            <h4>Réponse :</h4>';
    echo '<pre>', json_encode(json_decode($result), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';

}

function appelToken($url, $param) {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, queryParams($param));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // A supprimer pour la vraie vie
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    $server_output = curl_exec ($ch);

    return json_decode($server_output, true);
}


function appelKeys($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_FAILONERROR, true);
    curl_setopt($ch, CURLINFO_HEADER_OUT, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // A supprimer pour la vraie vie
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    $server_output = curl_exec ($ch);
    // Vérifie si une erreur survient
    if(curl_error($ch))
    {
        echo 'Erreur Curl : ' . curl_error($ch);
    }
    curl_close ($ch);

    return json_decode($server_output, true);
}

function keysToMap($json) {
    $ret = [];
    foreach ($json['keys'] as $k) {
        $ret[$k['kid']] = $k['x5c'][0];
    }

    return $ret;
}

function queryParams($params) {
    $ret = "";
    foreach($params as $k => $v) {
        if($k == 'client_secret')
            $ret .= $k . '='.$v.'&';
        else
            $ret .= $k . '='.urlencode($v).'&';
    }
    return rtrim($ret, '&');
}

function printParam($query) {
    $split = explode('&',  $query);
    echo '<pre>', json_encode($split, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), '</pre>';
}
