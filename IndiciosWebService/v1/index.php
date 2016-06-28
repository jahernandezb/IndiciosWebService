<?php
use Slim\Http\Response;
require_once '../include/DbHandler.php';
//require_once '../include/PassHash.php';
require_once '../include/Config.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

function Authenticate(\Slim\Route $route) {
	$headers = apache_request_headers();
	$response = array();
	$app = \Slim\Slim::getInstance();
	if (isset($headers['Authorization'])) {
		$db = new DbHandler();
		$apiKey = $headers['Authorization'];
		if (!$db->isValidApiKey($apiKey)) {
			$response ["error"] = true;
			$response ["code"] = ERROR_APIKEY_INVALID;
			EchoResponse(200, $response);
			$app->stop();
		} else {
			global $user_id;
			$user_id = $db->getUserId($apiKey);
		}
	} else {
		$response ["error"] = true;
		$response ["code"] = ERROR_APIKEY_MISSING;
		EchoResponse(200, $response);
		$app->stop();
	}
}

$app->post('/register', function() use($app) {
    VerifyRequiredParams(array('username', 'rfc', 'firstName', 'lastName', 'password'));
    $response = array();
    $username = $app->request->post('username');
    $rfc = $app->request->post('rfc');
    $firstName = $app->request->post('firstName');
    $lastName = $app->request->post('lastName');
    $password = $app->request->post('password');
    $db = new DbHandler();
    $response = $db->CreateUser($username, $rfc, $firstName, $lastName, $password);
    EchoResponse(200, $response);
});

$app->post('/login', function() use($app) {
    VerifyRequiredParams(array('username', 'password'));
    $username = $app->request->post('username');
    $password = $app->request->post('password');
    $response = array();
    $db = new DbHandler();
    if ($db->CheckLogin($username, $password)) {
        $userInfo = $db->GetUserInfo($username);
        if ($userInfo != null) {
            $response = $userInfo;
            $response["error"] = false;
        } else {
            $response["error"] = true;
            $response["code"] = ERROR_GET_USER_INFO;
        }
    } else {
        $response["error"] = true;
        $response["code"] = ERROR_LOGIN;
    }
    EchoResponse(200, $response);
});

function VerifyRequiredParams($required_fields) {
	$error = false;
	$request_params = array();
	$request_params = $_REQUEST;
	if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
		$app = \Slim\Slim::getInstance();
		parse_str($app->request()->getBody(), $request_params);
	}
	foreach ($required_fields as $field) {
		if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
			$error = true;
		}
	}
	if ($error) {
		$response = array();
		$app = \Slim\Slim::getInstance();
		$response ["error"] = true;
		$response ["code"] = ERROR_PARMS_MISSING;
		EchoResponse(200, $response);
		$app->stop();
	}
}

function EchoResponse($status_code, $response) {
	$app = \Slim\Slim::getInstance();
	$app->status($status_code);
	$app->contentType('application/json');
	echo json_encode($response);
}

$app->run ();
?>