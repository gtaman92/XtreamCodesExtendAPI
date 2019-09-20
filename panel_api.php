<?php
require "./includes/extend.php";

ini_set("memory_limit", -1);
if (!empty(ipTV_lib::$request["username"]) && !empty(ipTV_lib::$request["password"])) {
	$valid_actions = array("get_epg");
	$username = ipTV_lib::$request["username"];
	$password = ipTV_lib::$request["password"];
	$action = (!empty(ipTV_lib::$request["action"]) && in_array(ipTV_lib::$request["action"], $valid_actions) ? ipTV_lib::$request["action"] : "");
	$output = array();
	$output["user_info"] = array();

	if ($result = ipTV_Stream::GetUserInfo(NULL, $username, $password, true, true, true)) {
		switch ($action) {
		case "get_epg":
			if (!empty(ipTV_lib::$request["stream_id"]) && (is_null($result["exp_date"]) || (time() < $result["exp_date"]))) {
				$stream_id = intval(ipTV_lib::$request["stream_id"]);
				$from_now = (!empty(ipTV_lib::$request["from_now"]) && (0 < ipTV_lib::$request["from_now"]) ? true : false);
				$EPGs = GetEPGStream($stream_id, $from_now);
				echo json_encode($EPGs);
				exit();
			}
			else {
				echo json_encode(array());
				exit();
			}

			break;

		default:
			$categories = GetCategories();
			$url = (empty(ipTV_lib::$StreamingServers[SERVER_ID]["domain_name"]) ? ipTV_lib::$StreamingServers[SERVER_ID]["server_ip"] : ipTV_lib::$StreamingServers[SERVER_ID]["domain_name"]);
			$output["server_info"] = array("url" => $url, "port" => $_SERVER["SERVER_PORT"]);
			$output["user_info"]["username"] = $result["username"];
			$output["user_info"]["password"] = $result["password"];
			$output["user_info"]["auth"] = 1;

			if ($result["admin_enabled"] == 0) {
				$output["user_info"]["status"] = "Banned";
			}
			else if ($result["enabled"] == 0) {
				$output["user_info"]["status"] = "Disabled";
			}
			else {
				if (is_null($result["exp_date"]) || (time() < $result["exp_date"])) {
					$output["user_info"]["status"] = "Active";
				}
				else {
					$output["user_info"]["status"] = "Expired";
				}
			}

			$output["user_info"]["exp_date"] = $result["exp_date"];
			$output["user_info"]["is_trial"] = $result["is_trial"];
			$output["user_info"]["active_cons"] = $result["active_cons"];
			$output["user_info"]["created_at"] = $result["created_at"];
			$output["user_info"]["max_connections"] = $result["max_connections"];
			$output["user_info"]["allowed_output_formats"] = array_keys($result["output_formats"]);
			$output["available_channels"] = array();
			$live_num = $movie_num = 0;

			foreach ($result["channels"] as $channel ) {
				if ($channel["live"] == 1) {
					$live_num++;
					$stream_icon = $channel["stream_icon"];
				}
				else {
					$movie_num++;
					list() = json_decode($channel["movie_propeties"], true);
				}

				$output["available_channels"][$channel["id"]] = array("num" => $channel["live"] == 1 ? $live_num : $movie_num, "name" => $channel["stream_display_name"], "stream_type" => $channel["type_key"], "type_name" => $channel["type_name"], "stream_id" => $channel["id"], "stream_icon" => $stream_icon, "epg_channel_id" => $channel["channel_id"], "added" => $channel["added"], "category_id" => $channel["category_id"], "category_name" => $channel["category_name"], "category_parent_id" => !empty($channel["category_id"]) && !empty($categories[$channel["category_id"]]["parent_id"]) ? $categories[$channel["category_id"]]["parent_id"] : NULL, "series_no" => !empty($channel["series_no"]) ? $channel["series_no"] : NULL, "direct_source" => $channel["direct_source"], "direct_source_url" => $channel["direct_source"] == 1 ? json_decode($channel["stream_source"], true)[0] : "", "live" => $channel["live"], "container_extension" => $channel["container_extension"], "custom_sid" => $channel["custom_sid"]);
			}
		}
	}
	else {
		$output["user_info"]["auth"] = 0;}
	}

	echo json_encode($output);
}

?>
