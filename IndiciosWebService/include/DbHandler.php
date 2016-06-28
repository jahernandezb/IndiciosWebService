<?php
require_once '../include/Config.php';
require_once 'PassHash.php';

class DbHandler
{
    private $conn;

	function __construct() {
		require_once dirname ( __FILE__ ) . '/DbConnect.php';
		$db = new DbConnect ();
		$this->conn = $db->connect ();
	}

    public function CreateUser($username, $rfc, $firstName, $lastName, $password) {
        $response = array();
        if (!$this->IsUserExists($username)) {
			$passwordHash = PassHash::Hash($password);
            $apiKey = $this->GenerateApiKey();
            $pushToken = "0";
			$stmt = $this->conn->prepare("INSERT INTO usuarios(usuario_username, usuario_rfc, usuario_first_name, usuario_last_name, usuario_password, usuario_apikey, usuario_push_token) values(?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sssssss", $username, $rfc, $firstName, $lastName, $passwordHash, $apiKey, $pushToken);
            $result = $stmt->execute();
            $stmt->close ();
			if ($result) {
				$response['error'] = false;
                $response['code'] = SUCCESS;
			} else {
				$response['error'] = true;
                $response['code'] = ERROR_USER_REGISTER_FAIL;
			}
        } else {
            $response['error'] = true;
            $response['code'] = ERROR_USER_REGISTER_EXISTS;
        }
        return $response;
    }

    public function CheckLogin($username, $password) {
        $stmt = $this->conn->prepare("SELECT usuario_password FROM usuarios WHERE usuario_username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($passwordHash);
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $stmt->fetch();
            $stmt->close();
            if (PassHash::CheckPassword($passwordHash, $password)) {
                return true;
            } else {
                return false;
            }
        } else {
            $stmt->close();
            return false;
        }
    }

    private function IsUserExists($username) {
		$stmt = $this->conn->prepare ("SELECT usuario_id FROM usuarios WHERE usuario_username = ?");
		$stmt->bind_param("s", $username);
		$stmt->execute();
		$stmt->store_result();
		$num_rows = $stmt->num_rows;
		$stmt->close();
		return $num_rows > 0;
	}

    public function GetUserInfo($username) {
        $stmt = $this->conn->prepare("SELECT usuario_id, usuario_username, usuario_rfc, usuario_first_name, usuario_last_name, usuario_apikey FROM usuarios WHERE usuario_username = ?");
        $stmt->bind_param("s", $username);
        if ($stmt->execute()) {
            $stmt->bind_result($id, $username, $rfc, $firstName, $lastName, $apiKey);
            $stmt->fetch();
            $stmt->close();
            $userInfo = array();
            $userInfo["id"] = $id;
            $userInfo["username"] = $username;
            $userInfo["rfc"] = $rfc;
            $userInfo["firstName"] = $firstName;
            $userInfo["lastName"] = $lastName;
            $userInfo["apiKey"] = $apiKey;
            return $userInfo;
        } else {
            return null;
        }
    }

	private function GenerateApiKey() {
		return md5(uniqid(rand(), true));
	}

}

?>