<?php
error_reporting(0);
define("MAIN_DIR", "/home/xtreamcodes/");

@ini_set("user_agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0) Gecko/20100101 Firefox/9.0");
@ini_set("default_socket_timeout", 10);
define("IN_SCRIPT", true);
define("SOFTWARE", "iptv");
define("SCRIPT_NAME", "ipTV Panel");
define("SCRIPT_AUTHOR", "by Xtream-Codes");
define("SCRIPT_VERSION", "1.6.0");
define("IPTV_PANEL_DIR", MAIN_DIR . "iptv_xtream_codes/");
define("BIN_PATH", IPTV_PANEL_DIR . "bin/");
define("FFMPEG_PATH", file_exists(BIN_PATH . "ffmpeg") ? BIN_PATH . "ffmpeg" : "/usr/bin/ffmpeg");
define("FFPROBE_PATH", file_exists(BIN_PATH . "ffprobe") ? BIN_PATH . "ffprobe" : "/usr/bin/ffprobe");
define("STREAMS_PATH", IPTV_PANEL_DIR . "streams/");
define("MOVIES_IMAGES", IPTV_PANEL_DIR . "wwwdir/images/");
define("MOVIES_PATH", IPTV_PANEL_DIR . "movies/");
define("CREATED_CHANNELS", IPTV_PANEL_DIR . "created_channels/");
define("CRON_PATH", IPTV_PANEL_DIR . "crons/");
define("PHP_BIN", "/home/xtreamcodes/iptv_xtream_codes/php/bin/php");
define("ASYNC_DIR", IPTV_PANEL_DIR . "async_incs/");
define("TMP_DIR", IPTV_PANEL_DIR . "tmp/");
define("IPTV_CLIENT_AREA", IPTV_PANEL_DIR . "wwwdir/client_area/");
define("IPTV_CLIENT_AREA_TEMPLATES_PATH", IPTV_CLIENT_AREA . "templates/");
define("TV_ARCHIVE", IPTV_PANEL_DIR . "tv_archive/");

function isMobileDevice()
{
	$aMobileUA = array("/iphone/i" => "iPhone", "/ipod/i" => "iPod", "/ipad/i" => "iPad", "/android/i" => "Android", "/blackberry/i" => "BlackBerry", "/webos/i" => "Mobile");

	foreach ($aMobileUA as $sMobileKey => $sMobileOS ) {
		if (preg_match($sMobileKey, $_SERVER["HTTP_USER_AGENT"])) {
			return true;
		}
	}

	return false;
}

function CronChecking($file_name, $time = 600)
{
	if (file_exists($file_name)) {
		$pid = trim(file_get_contents($file_name));

		if (file_exists("/proc/" . $pid)) {
			if ((time() - filemtime($file_name)) < $time) {
				exit("Running...");
			}

			posix_kill($pid, 9);
		}
	}

	file_put_contents($file_name, getmypid());
	return false;
}

function BlockIP($ip, $reason)
{
	global $ipTV_db;

	if (in_array($ip, ipTV_Stream::getAllowedIPsAdmin(true))) {
		return NULL;
	}

	$ipTV_db->query("INSERT INTO `blocked_ips` (`ip`,`notes`,`date`) VALUES('%s','%s','%d')", $ip, $reason, time());

	if (0 < $ipTV_db->affected_rows()) {
		Servers::RunCommandServer(array_keys(ipTV_lib::$StreamingServers), "sudo /sbin/iptables -A INPUT -s $ip -j DROP");
	}
}

function CheckFlood()
{
	global $ipTV_db;
	$user_ip = ipTV_Stream::getUserIP();

	if (empty($user_ip)) {
		return NULL;
	}

	if ((ipTV_lib::$settings["flood_limit"] == 0) || in_array($user_ip, ipTV_Stream::getAllowedIPsAdmin(true))) {
		return NULL;
	}

	$restreamers = array_filter(array_unique(explode(",", ipTV_lib::$settings["flood_ips_exclude"])));

	if (in_array($user_ip, $restreamers)) {
		return NULL;
	}

	$user_activity_now = TMP_DIR . "user_activity_now.ips";
	$user_ip_file = TMP_DIR . $user_ip . ".flood";
	if (!file_exists($user_activity_now) || (20 <= time() - filemtime($user_activity_now))) {
		$ipTV_db->query("SELECT DISTINCT `user_ip`,t2.is_restreamer FROM `user_activity_now` t1 INNER JOIN `users` t2 ON t2.id = t1.user_id");
		$connected_ips = $ipTV_db->get_rows(true, "user_ip");
		file_put_contents($user_activity_now, json_encode($connected_ips));
	}
	else {
		$connected_ips = json_decode(file_get_contents($user_activity_now), true);
	}

	if (array_key_exists($user_ip, $connected_ips)) {
		if ($connected_ips[$user_ip]["is_restreamer"] == 0) {
			if (ipTV_lib::$settings["flood_apply_clients"] != 1) {
				return NULL;
			}
		}

		if ($connected_ips[$user_ip]["is_restreamer"] == 1) {
			if (ipTV_lib::$settings["flood_apply_restreamers"] != 1) {
				return NULL;
			}
		}
	}

	if (file_exists($user_ip_file)) {
		$flood_row = json_decode(file_get_contents($user_ip_file), true);
		$frequency_settings = ipTV_lib::$settings["flood_seconds"];
		$limit_attempts = ipTV_lib::$settings["flood_max_attempts"];
		$flood_limit = ipTV_lib::$settings["flood_limit"];

		if ($limit_attempts <= $flood_row["attempts"]) {
			$ipTV_db->query("INSERT INTO `blocked_ips` (`ip`,`notes`,`date`) VALUES('%s','%s','%d')", $user_ip, "FLOOD ATTACK", time());
			Servers::RunCommandServer(array_keys(ipTV_lib::$StreamingServers), "sudo /sbin/iptables -A INPUT -s $user_ip -j DROP");
			unlink($user_ip_file);
			return NULL;
		}

		if ((time() - $flood_row["last_request"]) <= $frequency_settings) {
			++$flood_row["requests"];

			if ($flood_limit <= $flood_row["requests"]) {
				++$flood_row["attempts"];
				$flood_row["requests"] = 0;
			}

			$flood_row["last_request"] = time();
			file_put_contents($user_ip_file, json_encode($flood_row), LOCK_EX);
		}
		else {
			$flood_row["attempts"] = $flood_row["requests"] = 0;
			$flood_row["last_request"] = time();
			file_put_contents($user_ip_file, json_encode($flood_row), LOCK_EX);
		}
	}
	else {
		file_put_contents($user_ip_file, json_encode(array("requests" => 0, "attempts" => 0, "last_request" => time())), LOCK_EX);
	}
}

function GetEPGs()
{
	global $ipTV_db;
	$ipTV_db->query("\n                    SELECT t1.*,COUNT(DISTINCT t2.`id`) as total_rows\n                    FROM `epg` t1\n                    LEFT  JOIN `epg_data` t2 ON t1.id = t2.epg_id\n                    GROUP BY t1.id\n                    ORDER BY t1.id DESC\n                    ");
	return 0 < $ipTV_db->num_rows() ? $ipTV_db->get_rows() : array();
}

function GetEPGStream($stream_id, $from_now = false)
{
	global $ipTV_db;
	$ipTV_db->query("SELECT `type`,`movie_propeties`,`epg_id`,`channel_id`FROM `streams` WHERE `id` = '%d'", $stream_id);

	if (0 < $ipTV_db->num_rows()) {
		$data = $ipTV_db->get_row();

		if ($data["type"] != 2) {
			if ($from_now) {
				$ipTV_db->query("SELECT * FROM `epg_data` WHERE `epg_id` = '%d' AND `channel_id` = '%s' AND `end` >= '%d'", $data["epg_id"], $data["channel_id"], time());
			}
			else {
				$ipTV_db->query("SELECT * FROM `epg_data` WHERE `epg_id` = '%d' AND `channel_id` = '%s'", $data["epg_id"], $data["channel_id"]);
			}

			return $ipTV_db->get_rows();
		}
		else {
			return $data["movie_propeties"];
		}
	}

	return array();
}

function GetEPGStreamPlayer($stream_id, $limit = 4)
{
	global $ipTV_db;
	$ipTV_db->query("SELECT `type`,`movie_propeties`,`epg_id`,`channel_id`FROM `streams` WHERE `id` = '%d'", $stream_id);

	if (0 < $ipTV_db->num_rows()) {
		$data = $ipTV_db->get_row();

		if ($data["type"] != 2) {
			$ipTV_db->query("SELECT * FROM `epg_data` WHERE `epg_id` = '%d' AND `channel_id` = '%s' AND `end` >= '%d' ORDER BY `start` ASC LIMIT %d", $data["epg_id"], $data["channel_id"], time(), $limit);
			return $ipTV_db->get_rows();
		}
		else {
			return $data["movie_propeties"];
		}
	}

	return array();
}

function GetTotalCPUsage()
{
	$total_cpu = intval(shell_exec("ps aux|awk 'NR > 0 { s +=\$3 }; END {print s}'"));
	$cores = intval(shell_exec("grep --count processor /proc/cpuinfo"));
	return intval($total_cpu / $cores);
}

function portal_auth($sn, $mac, $ver, $stb_type, $image_version, $device_id, $device_id2, $hw_version, $req_ip)
{
	global $ipTV_db;
	$ipTV_db->query("SELECT * FROM `mag_devices` WHERE `mac` = '%s'", $mac);

	if (0 < $ipTV_db->num_rows()) {
		$mag_info_db = $ipTV_db->get_row();
		$ipTV_db->query("SELECT * FROM `users` WHERE `id` = '%d' AND `is_mag` = 1", $mag_info_db["user_id"]);

		if (0 < $ipTV_db->num_rows()) {
			$user_info_db = $ipTV_db->get_row();
			$user_info_db["allowed_ips"] = json_decode($user_info_db["allowed_ips"], true);
		}

		$total_info = array_merge($mag_info_db, $user_info_db);
		$ipTV_db->query("UPDATE `mag_devices` SET `ip` = '%s' WHERE `mag_id` = '%d'", $req_ip, $total_info["mag_id"]);
		if ((empty($total_info["stb_type"]) && !empty($stb_type)) || (empty($total_info["sn"]) && !empty($sn)) || (empty($total_info["ver"]) && !empty($ver)) || (empty($total_info["image_version"]) && !empty($image_version)) || (empty($total_info["device_id"]) && !empty($device_id)) || (empty($total_info["device_id2"]) && !empty($device_id2)) || (empty($total_info["hw_version"]) && !empty($hw_version))) {
			if (empty($total_info["stb_type"]) && !empty($stb_type)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `stb_type` = '%s' WHERE `mag_id` = '%d'", $stb_type, $total_info["mag_id"]);
				$total_info["stb_type"] = $stb_type;
			}

			if (empty($total_info["sn"]) && !empty($sn)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `sn` = '%s' WHERE `mag_id` = '%d'", $sn, $total_info["mag_id"]);
				$total_info["sn"] = $sn;
			}

			if (empty($total_info["ver"]) && !empty($ver)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `ver` = '%s' WHERE `mag_id` = '%d'", $ver, $total_info["mag_id"]);
				$total_info["ver"] = $ver;
			}

			if (empty($total_info["image_version"]) && !empty($image_version)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `image_version` = '%s' WHERE `mag_id` = '%d'", $image_version, $total_info["mag_id"]);
				$total_info["image_version"] = $image_version;
			}

			if (empty($total_info["device_id"]) && !empty($device_id)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `device_id` = '%s' WHERE `mag_id` = '%d'", $device_id, $total_info["mag_id"]);
				$total_info["device_id"] = $device_id;
			}

			if (empty($total_info["device_id2"]) && !empty($device_id2)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `device_id2` = '%s' WHERE `mag_id` = '%d'", $device_id2, $total_info["mag_id"]);
				$total_info["device_id"] = $device_id2;
			}

			if (empty($total_info["hw_version"]) && !empty($hw_version)) {
				$ipTV_db->query("UPDATE `mag_devices` SET `hw_version` = '%s' WHERE `mag_id` = '%d'", $hw_version, $total_info["mag_id"]);
				$total_info["hw_version"] = $hw_version;
			}

			return array("total_info" => prepair_mag_cols($total_info), "mag_info_db" => prepair_mag_cols($mag_info_db), "fav_channels" => empty($mag_info_db["fav_channels"]) ? array() : json_decode($mag_info_db["fav_channels"], true));
		}
		else {
			if (($total_info["sn"] == $sn) && ($total_info["hw_version"] == $hw_version) && ($total_info["device_id2"] == $device_id2) && ($total_info["device_id"] == $device_id) && ($total_info["image_version"] == $image_version) && ($total_info["ver"] == $ver)) {
				return array("total_info" => prepair_mag_cols($total_info), "mag_info_db" => prepair_mag_cols($mag_info_db), "fav_channels" => empty($mag_info_db["fav_channels"]) ? array() : json_decode($mag_info_db["fav_channels"], true));
			}
		}
	}

	return false;
}

function get_from_cookie($cookie, $type)
{
	if (!empty($cookie)) {
		$explode = explode(";", $cookie);

		foreach ($explode as $data ) {
			$data = explode("=", $data);
			$output[trim($data[0])] = trim($data[1]);
		}

		switch ($type) {
		case "mac":
			if (array_key_exists("mac", $output)) {
				return base64_encode(strtoupper(urldecode($output["mac"])));
			}
		}
	}

	return false;
}

function prepair_mag_cols($array)
{
	$output = array();

	foreach ($array as $key => $value ) {
		if (($key == "mac") || ($key == "ver") || ($key == "hw_version")) {
			$output[$key] = base64_decode($value);
		}

		$output[$key] = $value;
	}

	unset($output["fav_channels"]);
	return $output;
}

function GetCategories($type = NULL, $remove_empty = false)
{
	global $ipTV_db;

	$query = "SELECT id, category_name, category_type FROM `stream_categories`";

	switch ($type) {
	case NULL:
		break;

	case "live":
		$query .= " WHERE category_type = 'live'";
		break;

	case "movie":
		$query .= " WHERE category_type = 'movie'";
		break;
	}

	$query .= " GROUP BY category_name, category_type ORDER BY id ASC;";
	$ipTV_db->query($query);
	return 0 < $ipTV_db->num_rows() ? $ipTV_db->get_rows(true, "id") : array();
}

function GenerateUniqueCode()
{
	return substr(md5(ipTV_lib::$settings["unique_id"]), 0, 15);
}

function encodeToUtf8($string)
{
	return mb_convert_encoding($string, "UTF-8", mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true));
}

function GenerateList($user_id, $device_key, $output_key = "", $force_download = false)
{
	global $ipTV_db;

	if (!RowExists("users", "id", $user_id)) {
		return false;
	}

	if (empty($device_key)) {
		return false;
	}

	if (empty($output_key)) {
		$ipTV_db->query("SELECT t1.output_ext FROM `access_output` t1 INNER JOIN `devices` t2 ON t2.default_output = t1.access_output_id AND `device_key` = '%s'", $device_key);
		$output_ext = $ipTV_db->get_col();
	}
	else {
		$ipTV_db->query("SELECT t1.output_ext FROM `access_output` t1 WHERE `output_key` = '%s'", $output_key);
		$output_ext = $ipTV_db->get_col();
	}

	if (empty($output_ext)) {
		return false;
	}

	$user_info = ipTV_Stream::GetUserInfo($user_id, NULL, NULL, true, true, false);

	if (empty($user_info)) {
		return false;
	}

	if (!empty($user_info["exp_date"]) && ($user_info["exp_date"] <= time())) {
		return false;
	}

	$ipTV_db->query("SELECT t1.*,t2.*\n                              FROM `devices` t1\n                              LEFT JOIN `access_output` t2 ON t2.access_output_id = t1.default_output\n                              WHERE t1.device_key = '%s' LIMIT 1", $device_key);
	$domain_name = ipTV_lib::$StreamingServers[SERVER_ID]["site_url"];

	if (0 < $ipTV_db->num_rows()) {
		$device_info = $ipTV_db->get_row();
		$data = "";

		if ($device_key == "starlivev5") {
			$output_array = array();
			$output_array["iptvstreams_list"] = array();
			$output_array["iptvstreams_list"]["@version"] = 1;
			$output_array["iptvstreams_list"]["group"] = array();
			$output_array["iptvstreams_list"]["group"]["name"] = "IPTV";
			$output_array["iptvstreams_list"]["group"]["channel"] = array();

			foreach ($user_info["channels"] as $channel_info ) {
				if ($channel_info["direct_source"] == 0) {
					$url = $domain_name . "{$channel_info["type_output"]}/{$user_info["username"]}/{$user_info["password"]}/";

					if ($channel_info["live"] == 0) {
						$url .= $channel_info["id"] . "." . $channel_info["container_extension"];
						$movie_propeties = json_decode($channel_info["movie_propeties"], true);

						if (!empty($movie_propeties["movie_image"])) {
							$icon = $movie_propeties["movie_image"];
						}
					}
					else {
						$url .= $channel_info["id"] . "." . $output_ext;
						$icon = $channel_info["stream_icon"];
					}
				}
				else {
					list($url) = json_decode($channel_info["stream_source"], true);
				}

				$channel = array();
				$channel["name"] = $channel_info["stream_display_name"];
				$icon = "";
				$channel["icon"] = $icon;
				$channel["stream_url"] = $url;
				$channel["stream_type"] = 0;
				$output_array["iptvstreams_list"]["group"]["channel"][] = $channel;
			}

			$data = json_encode((object) $output_array);
		}
		else {
			if (!empty($device_info["device_header"])) {
				$data = str_replace(array("{BOUQUET_NAME}", "{USERNAME}", "{PASSWORD}", "{SERVER_URL}", "{OUTPUT_KEY}"), array(ipTV_lib::$settings["bouquet_name"], $user_info["username"], $user_info["password"], $domain_name, $output_key), $device_info["device_header"]) . "\n";
			}

			if (!empty($device_info["device_conf"])) {
				if (preg_match("/\{URL\#(.*?)\}/", $device_info["device_conf"], $matches)) {
					$url_encoded_charts = str_split($matches[1]);
					$url_pattern = $matches[0];
				}
				else {
					$url_encoded_charts = array();
					$url_pattern = "{URL}";
				}

				foreach ($user_info["channels"] as $channel ) {
					if ($channel["direct_source"] == 0) {
						$url = $domain_name . "{$channel["type_output"]}/{$user_info["username"]}/{$user_info["password"]}/";
						$icon = "";

						if ($channel["live"] == 0) {
							$url .= $channel["id"] . "." . $channel["container_extension"];
							$movie_propeties = json_decode($channel["movie_propeties"], true);

							if (!empty($movie_propeties["movie_image"])) {
								$icon = $movie_propeties["movie_image"];
							}
						}
						else {
							$url .= $channel["id"] . "." . $output_ext;
							$icon = $channel["stream_icon"];
						}
					}
					else {
						list($url) = json_decode($channel["stream_source"], true);
					}

					$esr_id = ($channel["live"] == 1 ? 1 : 4097);
					$sid = (!empty($channel["custom_sid"]) ? $channel["custom_sid"] : ":0:1:0:0:0:0:0:0:0:");
					$data .= str_replace(array($url_pattern, "{ESR_ID}", "{SID}", "{CHANNEL_NAME}", "{CHANNEL_ID}", "{CATEGORY}", "{CHANNEL_ICON}"), array(str_replace($url_encoded_charts, array_map("urlencode", $url_encoded_charts), $url), $esr_id, $sid, $channel["stream_display_name"], $channel["channel_id"], $channel["category_name"], $icon), $device_info["device_conf"]) . "\r\n";
				}

				$data .= $device_info["device_footer"];
				$data = trim($data);
			}
		}

		if ($force_download === true) {
			header("Content-Description: File Transfer");
			header("Content-Type: application/octet-stream");
			header("Expires: 0");
			header("Cache-Control: must-revalidate");
			header("Pragma: public");
			header("Content-Disposition: attachment; filename=\"" . str_replace("{USERNAME}", $user_info["username"], $device_info["device_filename"]) . "\"");
			header("Content-Length: " . strlen($data));
			echo $data;
			exit();
		}

		return $data;
	}

	return false;
}

function GetServerConnections($end = NULL, $limit = false, $from = 0, $to = 0)
{
	global $ipTV_db;

	switch ($end) {
	case "open":
		$query = "\n                SELECT t1.*,t3.stream_display_name,t4.server_name as source_name,t5.server_name as dest_name\n                FROM `server_activity` t1\n                LEFT JOIN `streams` t3 ON t3.id = t1.stream_id\n                LEFT JOIN `streaming_servers` t4 ON t4.id = t1.source_server_id\n                LEFT JOIN `streaming_servers` t5 ON t5.id = t1.dest_server_id\n                WHERE ISNULL(t1.`date_end`)\n                ORDER BY t1.id DESC ";
		break;

	case "closed":
		$query = "\n                SELECT t1.*,t3.stream_display_name,t4.server_name as source_name,t5.server_name as dest_name\n                FROM `server_activity` t1\n                LEFT JOIN `streams` t3 ON t3.id = t1.stream_id\n                LEFT JOIN `streaming_servers` t4 ON t4.id = t1.source_server_id\n                LEFT JOIN `streaming_servers` t5 ON t5.id = t1.dest_server_id\n                WHERE t1.`date_end` IS NOT NULL\n                ORDER BY t1.id DESC ";
		break;

	default:
		$query = "\n                SELECT t1.*,t3.stream_display_name,t4.server_name as source_name,t5.server_name as dest_name\n                FROM `server_activity` t1\n                LEFT JOIN `streams` t3 ON t3.id = t1.stream_id\n                LEFT JOIN `streaming_servers` t4 ON t4.id = t1.source_server_id\n                LEFT JOIN `streaming_servers` t5 ON t5.id = t1.dest_server_id\n                ORDER BY (t1.`date_end` IS NOT NULL),t1.id DESC ";
	}

	if ($limit === true) {
		$query .= "LIMIT $from,$to";
	}

	$ipTV_db->query($query);
	$activities = array();

	if (0 < $ipTV_db->num_rows()) {
		$activities = $ipTV_db->get_rows();
	}

	return $activities;
}

function GetConnections($end, $server_id = NULL)
{
	global $ipTV_db;
	$extra = "";

	if (!is_null($server_id)) {
		$extra = "WHERE t1.server_id = '" . intval($server_id) . "'";
	}

	switch ($end) {
	case "open":
		$query = "\n                SELECT t1.*,t2.*,t3.*,t4.*,t5.mac,t6.bitrate\n                FROM `user_activity_now` t1\n                LEFT JOIN `users` t2 ON t2.id = t1.user_id\n                LEFT JOIN `streams` t3 ON t3.id = t1.stream_id\n                LEFT JOIN `streaming_servers` t4 ON t4.id = t1.server_id\n                LEFT JOIN `mag_devices` t5 on t5.user_id = t2.id\n                LEFT JOIN `streams_sys` t6 ON t6.stream_id = t1.stream_id AND t6.server_id = t1.server_id\n                $extra\n                ORDER BY t1.activity_id DESC";
		break;

	case "closed":
		$query = "\n                SELECT t1.*,t2.*,t3.*,t4.*,t5.mac,t6.bitrate\n                FROM `user_activity` t1\n                LEFT JOIN `users` t2 ON t2.id = t1.user_id\n                LEFT JOIN `streams` t3 ON t3.id = t1.stream_id\n                LEFT JOIN `streaming_servers` t4 ON t4.id = t1.server_id\n                LEFT JOIN `mag_devices` t5 on t5.user_id = t2.id\n                LEFT JOIN `streams_sys` t6 ON t6.stream_id = t1.stream_id AND t6.server_id = t1.server_id\n                $extra\n                ORDER BY t1.activity_id DESC";
		break;
	}

	$ipTV_db->query($query);
	return $ipTV_db->get_rows();
}

function Is_Running($file_name)
{
	$pid_running = false;

	if (file_exists($file_name)) {
		$data = file($file_name);

		foreach ($data as $pid ) {
			$pid = (int) $pid;
			if ((0 < $pid) && file_exists("/proc/" . $pid)) {
				$pid_running = $pid;
				break;
			}
		}
	}

	if ($pid_running && ($pid_running != getmypid())) {
		if (file_exists($file_name)) {
			file_put_contents($file_name, $pid);
		}

		return true;
	}
	else {
		file_put_contents($file_name, getmypid());
		return false;
	}
}

function crontab_refresh()
{
	if (file_exists(TMP_DIR . "crontab_refresh")) {
		return false;
	}

	$crons = scandir(CRON_PATH);
	$jobs = array();

	foreach ($crons as $cron ) {
		$full_path = CRON_PATH . $cron;

		if (!is_file($full_path)) {
			continue;
		}

		if (pathinfo($full_path, PATHINFO_EXTENSION) != "php") {
			continue;
		}

		$jobs[] = "*/1 * * * * " . PHP_BIN . " " . $full_path . " # Xtream-Codes IPTV Panel";
	}

	$crontab = trim(shell_exec("crontab -l"));

	if (!empty($crontab)) {
		$lines = explode("\n", $crontab);
		$lines = array_map("trim", $lines);

		if ($lines == $jobs) {
			file_put_contents(TMP_DIR . "crontab_refresh", 1);
			return true;
		}

		$counter = count($lines);

		for ($i = 0; $i < $counter; $i++) {
			if (stripos($lines[$i], CRON_PATH)) {
				unset($lines[$i]);
			}
		}

		foreach ($jobs as $job ) {
			array_push($lines, $job);
		}
	}
	else {
		$lines = $jobs;
	}

	shell_exec("crontab -r");
	$tmpfname = tempnam("/tmp", "crontab");
	$handle = fopen($tmpfname, "w");
	fwrite($handle, implode("\r\n", $lines) . "\r\n");
	fclose($handle);
	shell_exec("crontab $tmpfname");
	@unlink($tmpfname);
	file_put_contents(TMP_DIR . "crontab_refresh", 1);
}

function RowExists($table, $search_by, $needle)
{
	global $ipTV_db;
	$ipTV_db->query("SELECT * FROM `$table` WHERE `$search_by` = '%s'", $needle);

	if (0 < $ipTV_db->num_rows()) {
		return true;
	}

	return false;
}

function memory_usage()
{
	$memory_usage = trim(shell_exec("free -m"));

	if (empty($memory_usage)) {
		return false;
	}

	$data = explode("\n", $memory_usage);
	$memory_usage = array();
	$swap_usage = array();

	foreach ($data as $line ) {
		$output = preg_replace("!\s+!", " ", str_replace(":", "", $line));
		if (!strstr($output, "Mem") && !strstr($output, "Swap")) {
			continue;
		}

		$info = explode(" ", $output);

		if ($info[0] == "Mem") {
			$memory_usage["total"] = $info[1];
			$memory_usage["used"] = $info[2] - $info[6];

			if ($memory_usage["used"] < 0) {
				$memory_usage["used"] = $info[2];
			}

			$memory_usage["free"] = $info[3];
			$memory_usage["percent"] = sprintf("%0.2f", ($memory_usage["used"] / $memory_usage["total"]) * 100);
		}
		else {
			$swap_usage["total"] = $info[1];
			$swap_usage["used"] = $info[2];
			$swap_usage["free"] = $info[3];

			if ($swap_usage["total"] != 0) {
				$swap_usage["percent"] = sprintf("%0.2f", ($info[2] / $info[1]) * 100);
			}
			else {
				$swap_usage["percent"] = 0;
			}
		}
	}

	return array($memory_usage, $swap_usage);
}

function get_boottime()
{
	if (file_exists("/proc/uptime") && is_readable("/proc/uptime")) {
		$tmp = explode(" ", file_get_contents("/proc/uptime"));
		return secondsToTime(intval($tmp[0]));
	}

	return "";
}

function secondsToTime($inputSeconds)
{
	$secondsInAMinute = 60;
	$secondsInAnHour = 60 * $secondsInAMinute;
	$secondsInADay = 24 * $secondsInAnHour;
	$days = (int) floor($inputSeconds / $secondsInADay);
	$hourSeconds = $inputSeconds % $secondsInADay;
	$hours = (int) floor($hourSeconds / $secondsInAnHour);
	$minuteSeconds = $hourSeconds % $secondsInAnHour;
	$minutes = (int) floor($minuteSeconds / $secondsInAMinute);
	$remainingSeconds = $minuteSeconds % $secondsInAMinute;
	$seconds = (int) ceil($remainingSeconds);
	$final = "";

	if ($days != 0) {
		$final .= "{$days}d ";
	}

	if ($hours != 0) {
		$final .= "{$hours}h ";
	}

	if ($minutes != 0) {
		$final .= "{$minutes}m ";
	}

	$final .= "{$seconds}s";
	return $final;
}

class ipTV_lib
{
	/**
     * Input parameters
     *
     * @var		array
     */
	static 	public $request = array();
	/**
     * Database Instance
     *
     * @var		instance
     */
	static 	public $ipTV_db;
	/**
     * Settings
     *
     * @var		array
     */
	static 	public $settings = array();
	/**
     * Settings for Licence
     *
     * @var		array
     */
	static 	public $GetXtreamInfo = array();
	/**
     * Servers
     *
     * @var		array
     */
	static 	public $StreamingServers = array();
	static 	public $SegmentsSettings = array();
	static 	public $countries = array();

	static public function init()
	{
		if (!empty($_GET)) {
			self::cleanGlobals($_GET);
		}

		if (!empty($_POST)) {
			self::cleanGlobals($_POST);
		}

		if (!empty($_SESSION)) {
			self::cleanGlobals($_SESSION);
		}

		if (!empty($_COOKIE)) {
			self::cleanGlobals($_COOKIE);
		}

		$input = @self::parseIncomingRecursively($_GET, array());
		self::$request = @self::parseIncomingRecursively($_POST, $input);
		self::GetSettings();
		ini_set("date.timezone", self::$settings["default_timezone"]);
		self::GetXtreamInfo();
		self::$StreamingServers = self::GetServers();
		self::$SegmentsSettings = self::calculateSegNumbers();
		crontab_refresh();
	}

	static public function calculateSegNumbers()
	{
		$segments_settings = array();
		$segments_settings["seg_time"] = 10;
		$segments_settings["seg_list_size"] = 6;
		return $segments_settings;
	}

	static public function isValidMAC($mac)
	{
		return preg_match("/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/", $mac) == 1;
	}

	static public function GetSettings()
	{
		self::$ipTV_db->query("SELECT * FROM `settings`");
		$rows = self::$ipTV_db->get_row();

		foreach ($rows as $key => $val ) {
			self::$settings[$key] = $val;
		}

		self::$settings["allow_countries"] = json_decode(self::$settings["allow_countries"], true);

		if (array_key_exists("bouquet_name", self::$settings)) {
			self::$settings["bouquet_name"] = str_replace(" ", "_", self::$settings["bouquet_name"]);
		}
	}

	static public function GetServers()
	{
		self::$ipTV_db->query("SELECT * FROM `streaming_servers`");
		$servers = array();

		foreach (self::$ipTV_db->get_rows() as $row ) {
			if (!empty($row["vpn_ip"]) && (inet_pton($row["vpn_ip"]) !== false)) {
				$url = $row["vpn_ip"];
			}
			else if (empty($row["domain_name"])) {
				$url = $row["server_ip"];
			}
			else {
				$url = str_replace(array("http://", "/"), "", $row["domain_name"]);
			}

			$row["api_url"] = "http://" . $url . ":" . $row["http_broadcast_port"] . "/api.php?password=" . ipTV_lib::$settings["live_streaming_pass"];
			$row["site_url"] = "http://" . $url . ":" . $row["http_broadcast_port"] . "/";
			$row["api_url_ip"] = "http://" . $row["server_ip"] . ":" . $row["http_broadcast_port"] . "/api.php?password=" . ipTV_lib::$settings["live_streaming_pass"];
			$row["site_url_ip"] = "http://" . $row["server_ip"] . ":" . $row["http_broadcast_port"] . "/";
			$row["ssh_password"] = self::mc_decrypt($row["ssh_password"], md5(self::$settings["unique_id"]));
			$servers[$row["id"]] = $row;
		}

		return $servers;
	}

	static public function GetFFmpegArguments($parse_StreamArguments = array(), $add_default = true)
	{
		global $_LANG;
		self::$ipTV_db->query("SELECT * FROM `streams_arguments`");
		$rows = array();

		if (0 < self::$ipTV_db->num_rows()) {
			foreach (self::$ipTV_db->get_rows() as $row ) {
				if (array_key_exists($row["id"], $parse_StreamArguments)) {
					if (count($parse_StreamArguments[$row["id"]]) == 2) {
						$value = $parse_StreamArguments[$row["id"]]["val"];
					}
					else {
						$value = $parse_StreamArguments[$row["id"]]["value"];
					}
				}
				else {
					$value = ($add_default ? $row["argument_default_value"] : "");
				}

				if ($row["argument_type"] == "radio") {
					if (is_null($value) || (0 < $value)) {
						$no = false;
						$yes = true;
					}
					else {
						$no = true;
						$yes = false;
					}

					if ($yes) {
						$mode = "<input type=\"radio\" name=\"arguments[" . $row["id"] . "]\" value=\"1\" checked/> " . $_LANG["yes"] . " <input type=\"radio\" name=\"arguments[" . $row["id"] . "]\" value=\"0\" /> . " . $_LANG["no"];
					}
					else {
						$mode = "<input type=\"radio\" name=\"arguments[" . $row["id"] . "]\" value=\"1\" /> " . $_LANG["yes"] . " <input type=\"radio\" name=\"arguments[" . $row["id"] . "]\" value=\"0\" checked/> . " . $_LANG["no"];
					}
				}
				else if ($row["argument_type"] == "text") {
					$mode = "<input type=\"text\" name=\"arguments[" . $row["id"] . "]\" value=\"" . $value . "\" />";
				}

				$row["mode"] = $mode;
				$rows[$row["id"]] = $row;
			}
		}

		return $rows;
	}

	static public function mc_encrypt($encrypt, $key)
	{
		$encrypt = serialize($encrypt);
		$iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
		$key = pack("H*", $key);
		$mac = hash_hmac("sha256", $encrypt, substr(bin2hex($key), -32));
		$passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encrypt . $mac, MCRYPT_MODE_CBC, $iv);
		$encoded = base64_encode($passcrypt) . "|" . base64_encode($iv);
		return $encoded;
	}

	static public function mc_decrypt($decrypt, $key)
	{
		$decrypt = explode("|", $decrypt . "|");
		$decoded = base64_decode($decrypt[0]);
		$iv = base64_decode($decrypt[1]);

		if (strlen($iv) !== mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)) {
			return false;
		}

		$key = pack("H*", $key);
		$decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
		$mac = substr($decrypted, -64);
		$decrypted = substr($decrypted, 0, -64);
		$calcmac = hash_hmac("sha256", $decrypted, substr(bin2hex($key), -32));

		if ($calcmac !== $mac) {
			return false;
		}

		$decrypted = unserialize($decrypted);
		return $decrypted;
	}

	static public function formatOffset($offset)
	{
		$hours = $offset / 3600;
		$remainder = $offset % 3600;
		$sign = (0 < $hours ? "+" : "-");
		$hour = (int) abs($hours);
		$minutes = (int) abs($remainder / 60);
		if (($hour == 0) && ($minutes == 0)) {
			$sign = " ";
		}

		return $sign . str_pad($hour, 2, "0", STR_PAD_LEFT) . ":" . str_pad($minutes, 2, "0");
	}

	static public function GetTimeZones($current = NULL)
	{
		$utc = new DateTimeZone("UTC");
		$dt = new DateTime("now", $utc);
		$timezones = array();

		foreach (DateTimeZone::listIdentifiers() as $tz ) {
			$current_tz = new DateTimeZone($tz);
			$offset = $current_tz->getOffset($dt);
			$transition = $current_tz->getTransitions($dt->getTimestamp(), $dt->getTimestamp());
			$abbr = $transition[0]["abbr"];
			if (!is_null($current) && ($current == $tz)) {
				$timezones[] = "<option value=\"" . $tz . "\" selected>" . $tz . " [" . $abbr . " " . self::formatOffset($offset) . "]</option>";
			}
			else {
				$timezones[] = "<option value=\"" . $tz . "\">" . $tz . " [" . $abbr . " " . self::formatOffset($offset) . "]</option>";
			}
		}

		return $timezones;
	}

	static public function GetCurrentTimeOffset()
	{
		$utc = new DateTimeZone("UTC");
		$dt = new DateTime("now", $utc);
		$current_timezone = ipTV_lib::$settings["default_timezone"];
		$current_tz = new DateTimeZone($current_timezone);
		$offset = $current_tz->getOffset($dt);
		return self::formatOffset($offset);
	}

	static public function SimpleWebGet($url, $save_cache = false)
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($ch, CURLOPT_TIMEOUT, 30);
		curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
		$res = curl_exec($ch);
		curl_close($ch);

		if ($res !== false) {
			if ($save_cache) {
				$unique_id = uniqid();
				file_put_contents(TMP_DIR . $unique_id, $res);
				return TMP_DIR . $unique_id;
			}
		}

		return trim($res);
	}

	static public function curlMultiRequest($urls, $callback = NULL, $array_key = "raw")
	{
		if (empty($urls)) {
			return array();
		}

		$ch = array();
		$results = array();
		$mh = curl_multi_init();

		foreach ($urls as $key => $val ) {
			$ch[$key] = curl_init();
			curl_setopt($ch[$key], CURLOPT_URL, $val["url"]);
			curl_setopt($ch[$key], CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch[$key], CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch[$key], CURLOPT_CONNECTTIMEOUT, 120);
			curl_setopt($ch[$key], CURLOPT_TIMEOUT, 120);
			curl_setopt($ch[$key], CURLOPT_MAXREDIRS, 10);

			if ($val["postdata"] != NULL) {
				curl_setopt($ch[$key], CURLOPT_POST, true);
				curl_setopt($ch[$key], CURLOPT_POSTFIELDS, http_build_query($val["postdata"]));
			}

			curl_multi_add_handle($mh, $ch[$key]);
		}

		$running = NULL;

		do {
			curl_multi_exec($mh, $running);
		} while (0 < $running);

		foreach ($ch as $key => $val ) {
			$results[$key] = curl_multi_getcontent($val);

			if ($callback != NULL) {
				$results[$key] = call_user_func($callback, $results[$key], true);

				if (isset($results[$key][$array_key])) {
					$results[$key] = $results[$key][$array_key];
				}
			}

			if (!$results[$key]) {
				$results[$key] = array();
				ipTV_lib::SaveLog("Server [$key] is DOWN!");
			}

			curl_multi_remove_handle($mh, $val);
		}

		curl_multi_close($mh);
		return $results;
	}

	static public function cleanGlobals(&$data, $iteration = 0)
	{
		if (10 <= $iteration) {
			return NULL;
		}

		foreach ($data as $k => $v ) {
			if (is_array($v)) {
				self::cleanGlobals($data[$k], ++$iteration);
			}
			else {
				$v = str_replace(chr("0"), "", $v);
				$v = str_replace("\000", "", $v);
				$v = str_replace("\000", "", $v);
				$v = str_replace("../", "&#46;&#46;/", $v);
				$v = str_replace("&#8238;", "", $v);
				$data[$k] = $v;
			}
		}
	}

	static public function parseIncomingRecursively(&$data, $input = array(), $iteration = 0)
	{
		if (20 <= $iteration) {
			return $input;
		}

		if (!is_array($data)) {
			return $input;
		}

		foreach ($data as $k => $v ) {
			if (is_array($v)) {
				$input[$k] = self::parseIncomingRecursively($data[$k], array(), $iteration + 1);
			}
			else {
				$k = self::parseCleanKey($k);
				$v = self::parseCleanValue($v);
				$input[$k] = $v;
			}
		}

		return $input;
	}

	static public function parseCleanKey($key)
	{
		if ($key === "") {
			return "";
		}

		$key = htmlspecialchars(urldecode($key));
		$key = str_replace("..", "", $key);
		$key = preg_replace("/\_\_(.+?)\_\_/", "", $key);
		$key = preg_replace("/^([\w\.\-\_]+)$/", "\$1", $key);
		return $key;
	}

	static public function parseCleanValue($val)
	{
		if ($val == "") {
			return "";
		}

		$val = str_replace("&#032;", " ", stripslashes($val));
		$val = str_replace(array("\r\n", "\n\r", "\r"), "\n", $val);
		$val = str_replace("<!--", "&#60;&#33;--", $val);
		$val = str_replace("-->", "--&#62;", $val);
		$val = str_ireplace("<script", "&#60;script", $val);
		$val = preg_replace("/&amp;#([0-9]+);/s", "&#\1;", $val);
		$val = preg_replace("/&#(\d+?)([^\d;])/i", "&#\1;\2", $val);
		return trim($val);
	}

	static public function SaveLog($msg)
	{
		self::$ipTV_db->query("INSERT INTO `panel_logs` (`log_message`,`date`) VALUES('%s','%d')", $msg, time());
	}

	static public function GetXtreamInfo()
	{
		self::$ipTV_db->query("SELECT * from `xtream_main` WHERE `id` = 1");

		if (0 < self::$ipTV_db->num_rows()) {
			self::$GetXtreamInfo = self::$ipTV_db->get_row();
		}
	}

	static public function IsEmail($email)
	{
		$isValid = true;
		$atIndex = strrpos($email, "@");
		if (is_bool($atIndex) && !$atIndex) {
			$isValid = false;
		}
		else {
			$domain = substr($email, $atIndex + 1);
			$local = substr($email, 0, $atIndex);
			$localLen = strlen($local);
			$domainLen = strlen($domain);
			if (($localLen < 1) || (64 < $localLen)) {
				$isValid = false;
			}
			else {
				if (($domainLen < 1) || (255 < $domainLen)) {
					$isValid = false;
				}
				else {
					if (($local[0] == ".") || ($local[$localLen - 1] == ".")) {
						$isValid = false;
					}
					else if (preg_match("/\.\./", $local)) {
						$isValid = false;
					}
					else if (!preg_match("/^[A-Za-z0-9\-\.]+$/", $domain)) {
						$isValid = false;
					}
					else if (preg_match("/\.\./", $domain)) {
						$isValid = false;
					}
					else if (!preg_match("/^(\\\\.|[A-Za-z0-9!#%&`_=\/$'*+?^{}|~.-])+$/", str_replace("\\\\", "", $local))) {
						if (!preg_match("/^\"(\\\\\"|[^\"])+\"$/", str_replace("\\\\", "", $local))) {
							$isValid = false;
						}
					}
				}
			}

			if ($isValid && !checkdnsrr($domain, "MX") || checkdnsrr($domain, "A")) {
				$isValid = false;
			}
		}

		return $isValid;
	}

	static public function GenerateString($length = 10)
	{
		$chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789qwertyuiopasdfghjklzxcvbnm";
		$str = "";
		$max = strlen($chars) - 1;

		for ($i = 0; $i < $length; $i++) {
			$str .= $chars[rand(0, $max)];
		}

		return $str;
	}

	static public function array_values_recursive($array)
	{
		$arrayValues = array();

		foreach ($array as $value ) {
			if (is_scalar($value) || is_resource($value)) {
				$arrayValues[] = $value;
			}
			else if (is_array($value)) {
				$arrayValues = array_merge($arrayValues, self::array_values_recursive($value));
			}
		}

		return $arrayValues;
	}

	static public function BuildTreeArray($servers)
	{
		$tree = array();

		foreach ($servers as $server ) {
			if (!isset($tree[$server["parent_id"]])) {
				$tree[$server["parent_id"]] = array();
			}
			else {
				continue;
			}

			foreach ($servers as $second_parse_servers ) {
				if ($second_parse_servers["parent_id"] == $server["parent_id"]) {
					$tree[$server["parent_id"]][] = $second_parse_servers["server_id"];
				}
			}
		}

		ksort($tree);
		return $tree;
	}

	static public function PrintTree($array, $index = 0)
	{
		$out = "";
		if (isset($array[$index]) && is_array($array[$index])) {
			$out = "<ul>";

			foreach ($array[$index] as $track ) {
				$out .= "<li><a href=\"#\">" . ipTV_lib::$StreamingServers[$track]["server_name"] . "</a>";
				$out .= self::PrintTree($array, $track);
				$out .= "</li>";
			}

			$out .= "</ul>";
		}

		return $out;
	}

	static public function add_quotes_string($string)
	{
		return "\"" . $string . "\"";
	}

	static public function valid_ip_cidr($cidr, $must_cidr = false)
	{
		if (!preg_match("/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]{1,2})?$/", $cidr)) {
			$return = false;
		}
		else {
			$return = true;
		}

		if ($return == true) {
			$parts = explode("/", $cidr);
			$ip = $parts[0];
			$netmask = $parts[1];
			$octets = explode(".", $ip);

			foreach ($octets as $octet ) {
				if (255 < $octet) {
					$return = false;
				}
			}

			if ((($netmask != "") && (32 < $netmask) && !$must_cidr) || ((($netmask == "") || (32 < $netmask)) && $must_cidr)) {
				$return = false;
			}
		}

		return $return;
	}
}

class ipTV_db
{
	/**
     * Amount of queries made
     *
     * @access private
     * @var int
     */
	public $num_queries = 0;
	/**
     * MySQL result, which is either a resource or boolean.
     *
     * @access protected
     * @var mixed
     */
	public $result;
	/**
     * Last query made
     *
     * @access private
     * @var array
     */
	public $last_query;
	/**
     * Database Username
     *
     * @access protected
     * @var string
     */
	protected $dbuser;
	/**
     * Database Password
     *
     * @access protected
     * @var string
     */
	protected $dbpassword;
	/**
     * Database Name
     *
     * @access protected
     * @var string
     */
	protected $dbname;
	/**
     * Database Host
     *
     * @access protected
     * @var string
     */
	protected $dbhost;
	/**
     * Database Handle
     *
     * @access protected
     * @var string
     */
	public $dbh;

	public function __construct($dbuser, $dbpassword, $dbname, $dbhost)
	{
		$this->dbuser = $dbuser;
		$this->dbpassword = $dbpassword;
		$this->dbname = $dbname;
		$this->dbhost = $dbhost;
		$this->db_connect();
	}

	public function close_mysql()
	{
		mysqli_close($this->dbh);
		return true;
	}

	public function db_connect()
	{
		$this->dbh = mysqli_connect($this->dbhost, $this->dbuser, $this->dbpassword, $this->dbname, 3306);

		if (!$this->dbh) {
			exit("Connect Error: " . mysqli_connect_error());
		}

		return true;
	}

	public function query($query, $buffered = false)
	{
		if ($this->dbh) {
			$numargs = func_num_args();
			$arg_list = func_get_args();
			$next_arg_list = array();

			for ($i = 1; $i < $numargs; $i++) {
				$next_arg_list[] = mysqli_real_escape_string($this->dbh, $arg_list[$i]);
			}

			$query = vsprintf($query, $next_arg_list);
			$this->last_query = $query;

			if ($buffered === true) {
				$this->result = mysqli_query($this->dbh, $query, MYSQLI_USE_RESULT);
			}
			else {
				$this->result = mysqli_query($this->dbh, $query);
			}

			if (!$this->result) {
				ipTV_lib::SaveLog("MySQL Query Failed [" . $query . "]: " . mysqli_error($this->dbh));
			}

			$this->num_queries++;
		}
	}

	public function get_rows($use_id = false, $column_as_id = "", $unique_row = true)
	{
		if ($this->dbh && $this->result) {
			$rows = array();

			if (0 < $this->num_rows()) {
				while ($row = mysqli_fetch_array($this->result, MYSQLI_ASSOC)) {
					if ($use_id && array_key_exists($column_as_id, $row)) {
						if (!isset($rows[$row[$column_as_id]])) {
							$rows[$row[$column_as_id]] = array();
						}

						if (!$unique_row) {
							$rows[$row[$column_as_id]][] = $row;
						}
						else {
							$rows[$row[$column_as_id]] = $row;
						}
					}
					else {
						$rows[] = $row;
					}
				}
			}

			return $rows;
		}

		return false;
	}

	public function get_row()
	{
		if ($this->dbh && $this->result) {
			$row = array();

			if (0 < $this->num_rows()) {
				$row = mysqli_fetch_array($this->result, MYSQLI_ASSOC);
			}

			return $row;
		}

		return false;
	}

	public function get_col()
	{
		if ($this->dbh && $this->result) {
			$row = false;

			if (0 < $this->num_rows()) {
				$row = mysqli_fetch_array($this->result, MYSQLI_NUM);
				$row = $row[0];
			}

			return $row;
		}

		return false;
	}

	public function affected_rows()
	{
		$mysqli_affected_rows = mysqli_affected_rows($this->dbh);
		return empty($mysqli_affected_rows) ? 0 : $mysqli_affected_rows;
	}

	public function simple_query($query)
	{
		$this->result = mysqli_query($this->dbh, $query);

		if (!$this->result) {
			ipTV_lib::SaveLog("MySQL Query Failed [" . $query . "]: " . mysqli_error($this->dbh));
		}
	}

	public function escape($string)
	{
		return mysqli_real_escape_string($this->dbh, $string);
	}

	public function num_fields()
	{
		$mysqli_num_fields = mysqli_num_fields($this->result);
		return empty($mysqli_num_fields) ? 0 : $mysqli_num_fields;
	}

	public function last_insert_id()
	{
		$mysql_insert_id = mysqli_insert_id($this->dbh);
		return empty($mysql_insert_id) ? 0 : $mysql_insert_id;
	}

	public function num_rows()
	{
		$mysqli_num_rows = mysqli_num_rows($this->result);
		return empty($mysqli_num_rows) ? 0 : $mysqli_num_rows;
	}
}

class ipTV_Stream
{
	/**
     * Database Instance
     *
     * @var		instance
     */
	static 	public $ipTV_db;
	static 	public $AllowedIPs = array();

	static public function getAllowedIPsAdmin($reg_users = true)
	{
		if (!empty(self::$AllowedIPs)) {
			return self::$AllowedIPs;
		}

		$ips = array("127.0.0.1", $_SERVER["SERVER_ADDR"]);

		foreach (ipTV_lib::$StreamingServers as $server_id => $server_info ) {
			$ips[] = gethostbyname($server_info["server_ip"]);
		}

		if ($reg_users) {
			self::$ipTV_db->query("SELECT `ip` FROM `reg_users` WHERE `member_group_id` = 1 AND `last_login` >= '%d'", strtotime("-2 hour"));
			$ips = array_merge($ips, ipTV_lib::array_values_recursive(self::$ipTV_db->get_rows()));
		}

		if (!empty(ipTV_lib::$settings["allowed_ips_admin"])) {
			$ips = array_merge($ips, explode(",", ipTV_lib::$settings["allowed_ips_admin"]));
		}

		if (!empty(ipTV_lib::$GetXtreamInfo["root_ip"])) {
			$ips[] = ipTV_lib::$GetXtreamInfo["root_ip"];
		}

		if (!file_exists(TMP_DIR . "cloud_ips") || (900 <= time() - filemtime(TMP_DIR . "cloud_ips"))) {
			$contents = ipTV_lib::SimpleWebGet("http://xtream-codes.com/cloud_ips");

			if (!empty($contents)) {
				file_put_contents(TMP_DIR . "cloud_ips", $contents);
			}
		}

		if (file_exists(TMP_DIR . "cloud_ips")) {
			$ips = array_filter(array_merge($ips, array_map("trim", file(TMP_DIR . "cloud_ips"))));
		}

		self::$AllowedIPs = $ips;
		return array_unique($ips);
	}

	static public function FileParser($FileName)
	{
		if (!file_exists($FileName)) {
			return false;
		}

		$streams = array();
		$need_stream_url = false;
		$fp = fopen($FileName, "r");

		while (!feof($fp)) {
			$line = urldecode(trim(fgets($fp)));

			if (empty($line)) {
				continue;
			}

			if (stristr($line, "#EXTM3U")) {
				continue;
			}

			if (!stristr($line, "#EXTINF") && $need_stream_url) {
				$streams[$stream_name] = json_encode(array($line));
				$need_stream_url = false;
				continue;
			}

			if (stristr($line, "#EXTINF")) {
				$stream_name = trim(end(explode(",", $line)));
				$need_stream_url = true;
			}
		}

		return $streams;
	}

	static public function CanServerStream($server_id, $stream_id, $type = "live", $extension = NULL)
	{
		if ($type == "live") {
			self::$ipTV_db->query("\n                    SELECT *\n                    FROM `streams` t1\n                    INNER JOIN `streams_types` t4 ON t4.type_id = t1.type\n                    INNER JOIN `streams_sys` t2 ON t2.stream_id = t1.id AND t2.pid IS NOT NULL AND t2.server_id = '%d'\n                    WHERE t1.`id` = '%d'", $server_id, $stream_id);
		}
		else {
			self::$ipTV_db->query("\n                    SELECT * \n                    FROM `streams` t1\n                    INNER JOIN `streams_sys` t2 ON t2.stream_id = t1.id AND t2.pid IS NOT NULL AND t2.server_id = '%d' AND t2.stream_status = 0 AND t2.to_analyze = 0 AND t2.pid IS NOT NULL\n                    INNER JOIN `movie_containers` t3 ON t3.container_id = t1.target_container_id AND t3.container_extension = '%s'\n                    WHERE t1.`id` = '%d'", $server_id, $extension, $stream_id);
		}

		if (self::$ipTV_db->num_rows()) {
			$stream_info = self::$ipTV_db->get_row();
			return $stream_info;
		}

		return false;
	}

	static public function Redirect($user_info, $USER_IP, $user_country_code, $external_device, $type)
	{
		if ((count(ipTV_lib::$StreamingServers) <= 1) || !array_key_exists(SERVER_ID, ipTV_lib::$StreamingServers)) {
			return false;
		}

		parse_str($_SERVER["QUERY_STRING"], $query);
		$available_servers = array();

		if ($type == "live") {
			$stream_id = $query["stream"];
			$extension = $query["extension"];

			if ($extension == "m3u8") {
				self::$ipTV_db->query("SELECT * FROM `user_activity_now` WHERE container = 'hls' AND `user_id` = '%d' AND `stream_id` = '%d' LIMIT 1", $user_info["id"], $stream_id);

				if (0 < self::$ipTV_db->num_rows()) {
					$activity_info = self::$ipTV_db->get_row();

					if ($activity_info["server_id"] == SERVER_ID) {
						return false;
					}

					if ($channel_info[$activity_info["server_id"]] = self::CanServerStream($activity_info["server_id"], $stream_id, $type, isset($extension) ? $extension : NULL)) {
						$valid_time = 0;
						$md5_key = md5(ipTV_lib::$settings["live_streaming_pass"] . ipTV_lib::$StreamingServers[$activity_info["server_id"]]["server_ip"] . $USER_IP . $stream_id . $query["username"] . $query["password"] . $valid_time);
						header("Location: " . ipTV_lib::$StreamingServers[$activity_info["server_id"]]["site_url"] . $_SERVER["PHP_SELF"] . "?" . $_SERVER["QUERY_STRING"] . "&hash=" . $md5_key . "&time=" . $valid_time . "&external_device=" . $external_device . "&pid=" . $channel_info[$activity_info["server_id"]]["pid"]);
						ob_end_flush();
						exit();
					}
				}
			}
		}
		else {
			$stream = pathinfo($query["stream"]);
			$stream_id = intval($stream["filename"]);
			$extension = $stream["extension"];
		}

		$channel_info = array();

		foreach (ipTV_lib::$StreamingServers as $serverID => $server_info ) {
			if (ipTV_lib::$StreamingServers[$serverID]["status"] != 1) {
				continue;
			}

			if (isset($query["stream"])) {
				if ($channel_info[$serverID] = self::CanServerStream($serverID, $stream_id, $type, isset($extension) ? $extension : NULL)) {
					$available_servers[] = $serverID;
				}
			}
		}

		if (empty($available_servers)) {
			return false;
		}

		self::$ipTV_db->query("SELECT a.server_id, SUM(ISNULL(a.date_end)) AS online_clients FROM `user_activity_now` a WHERE a.server_id IN (" . implode(",", $available_servers) . ") GROUP BY a.server_id ORDER BY online_clients ASC");
		$CanAcceptCons = array();

		foreach (self::$ipTV_db->get_rows() as $row ) {
			if ($row["online_clients"] < ipTV_lib::$StreamingServers[$row["server_id"]]["total_clients"]) {
				$CanAcceptCons[$row["server_id"]] = $row["online_clients"];
			}
			else {
				$CanAcceptCons[$row["server_id"]] = false;
			}
		}

		foreach (array_keys(ipTV_lib::$StreamingServers) as $server_id ) {
			if (in_array($server_id, $available_servers)) {
				if (!array_key_exists($server_id, $CanAcceptCons)) {
					if (0 < ipTV_lib::$StreamingServers[$server_id]["total_clients"]) {
						$CanAcceptCons[$server_id] = 0;
					}
					else {
						$CanAcceptCons[$server_id] = false;
					}
				}
			}
		}

		$CanAcceptCons = array_filter($CanAcceptCons, "is_numeric");

		foreach (array_keys($CanAcceptCons) as $server_id ) {
			if ($server_id == SERVER_ID) {
				continue;
			}

			if (ipTV_lib::$StreamingServers[$server_id]["status"] != 1) {
				unset($CanAcceptCons[$server_id]);
			}
		}

		if (!empty($CanAcceptCons)) {
			$split_clients = ipTV_lib::$settings["split_clients"];

			if ($split_clients == "equal") {
				$keys = array_keys($CanAcceptCons);
				$values = array_values($CanAcceptCons);
				array_multisort($values, SORT_ASC, $keys, SORT_ASC);
				$CanAcceptCons = array_combine($keys, $values);
			}
			else {
				$keys = array_keys($CanAcceptCons);
				$values = array_values($CanAcceptCons);
				array_multisort($values, SORT_ASC, $keys, SORT_DESC);
				$CanAcceptCons = array_combine($keys, $values);
				end($CanAcceptCons);
			}

			foreach (array_keys($CanAcceptCons) as $server_id ) {
				if (empty(ipTV_lib::$StreamingServers[$server_id]["geoip_countries"])) {
					$geoip_countries = array();
				}
				else {
					$geoip_countries = json_decode(ipTV_lib::$StreamingServers[$server_id]["geoip_countries"], true);
				}

				if ((ipTV_lib::$StreamingServers[$server_id]["enable_geoip"] == 1) && in_array($user_country_code, $geoip_countries)) {
					$redirect_id = $server_id;
					break;
				}
			}

			if (!isset($redirectid)) {
				$redirect_id = key($CanAcceptCons);
			}

			if (($user_info["force_server_id"] != 0) && array_key_exists($user_info["force_server_id"], $CanAcceptCons)) {
				$redirect_id = $user_info["force_server_id"];
			}

			if ($redirect_id != SERVER_ID) {
				if ($extension == "m3u8") {
					$valid_time = 0;
				}
				else {
					$valid_time = time() + 10;
				}

				$md5_key = md5(ipTV_lib::$settings["live_streaming_pass"] . ipTV_lib::$StreamingServers[$redirect_id]["server_ip"] . $USER_IP . $stream_id . $query["username"] . $query["password"] . $valid_time);
				header("Location: " . ipTV_lib::$StreamingServers[$redirect_id]["site_url"] . $_SERVER["PHP_SELF"] . "?" . $_SERVER["QUERY_STRING"] . "&hash=" . $md5_key . "&time=" . $valid_time . "&pid=" . $channel_info[$redirect_id]["pid"] . "&external_device=" . $external_device);
				ob_end_flush();
				exit();
			}
		}

		return false;
	}

	static public function GetUserInfo($user_id = NULL, $username = NULL, $password = NULL, $get_ChannelIDS = false, $getBouquetInfo = false, $get_cons = false, $type = array(), $parse_adults = false)
	{
		if (empty($user_id)) {
			self::$ipTV_db->query("SELECT * FROM `users` WHERE `username` = '%s' AND `password` = '%s' LIMIT 1", $username, $password);
		}
		else {
			self::$ipTV_db->query("SELECT * FROM `users` WHERE `id` = '%d'", $user_id);
		}

		if (0 < self::$ipTV_db->num_rows()) {
			$user_info = self::$ipTV_db->get_row();
			$user_info["bouquet"] = json_decode($user_info["bouquet"], true);
			$user_info["allowed_ips"] = json_decode($user_info["allowed_ips"], true);
			$user_info["allowed_ua"] = json_decode($user_info["allowed_ua"], true);

			if ($get_cons) {
				self::$ipTV_db->query("SELECT COUNT(`activity_id`) FROM `user_activity_now` WHERE `user_id` = '%d'", $user_info["id"]);
				$user_info["active_cons"] = self::$ipTV_db->get_col();
				$user_info["pair_line_info"] = array();
				if (!is_null($user_info["pair_id"]) && RowExists("users", "id", $user_info["pair_id"])) {
					self::$ipTV_db->query("SELECT COUNT(`activity_id`) FROM `user_activity_now` WHERE `user_id` = '%d'", $user_info["pair_id"]);
					$user_info["pair_line_info"]["active_cons"] = self::$ipTV_db->get_col();
					self::$ipTV_db->query("SELECT max_connections FROM `users` WHERE `id` = '%d'", $user_info["pair_id"]);
					$user_info["pair_line_info"]["max_connections"] = self::$ipTV_db->get_col();
				}
			}
			else {
				$user_info["active_cons"] = "N/A";
			}

			if ($user_info["is_mag"] == 1) {
				self::$ipTV_db->query("SELECT * FROM `mag_devices` WHERE `user_id` = '%d' LIMIT 1", $user_info["id"]);

				if (0 < self::$ipTV_db->num_rows()) {
					$user_info["mag_device"] = self::$ipTV_db->get_row();
				}
			}

			self::$ipTV_db->query("SELECT *\n                                    FROM `access_output` t1\n                                    INNER JOIN `user_output` t2 ON t1.access_output_id = t2.access_output_id\n                                    WHERE t2.user_id = '%d'", $user_info["id"]);
			$user_info["output_formats"] = self::$ipTV_db->get_rows(true, "output_ext");

			if ($get_ChannelIDS) {
				$channel_ids = array();
				self::$ipTV_db->query("SELECT `bouquet_channels` FROM `bouquets` WHERE `id` IN (" . implode(",", $user_info["bouquet"]) . ")");

				foreach (self::$ipTV_db->get_rows() as $row ) {
					$channel_ids = array_merge($channel_ids, json_decode($row["bouquet_channels"], true));
				}

				$user_info["channel_ids"] = array_unique($channel_ids);
				$user_info["channels"] = array();
				if ($getBouquetInfo && !empty($user_info["channel_ids"])) {
					$get_scat = "";

					if (!empty($type)) {
						$get_scat = " AND (";

						foreach ($type as $tp ) {
							$get_scat .= " t2.type_key = '" . self::$ipTV_db->escape($tp) . "' OR";
						}

						$get_scat = substr($get_scat, 0, -2);
						$get_scat .= ")";
					}

					self::$ipTV_db->query("SELECT t1.*,t2.*,t3.category_name,t4.*\n                                            FROM `streams` t1 \n                                            LEFT JOIN  `stream_categories` t3 on t3.id = t1.category_id\n                                            INNER JOIN `streams_types` t2 ON t2.type_id = t1.type $get_scat\n                                            LEFT JOIN `movie_containers` t4 ON t4.container_id = t1.target_container_id\n                                            WHERE t1.`id` IN(" . implode(",", $user_info["channel_ids"]) . ") \n                                            ORDER BY FIELD(t1.id, " . implode(",", $user_info["channel_ids"]) . ");");
					$user_info["channels"] = self::$ipTV_db->get_rows();

					if ($parse_adults) {
						$total_adults = 0;

						foreach ($user_info["channels"] as $key => $stream ) {
							$user_info["channels"][$key]["is_adult"] = (strtolower($stream["category_name"]) == "for adults" ? 1 : 0);
						}
					}
				}
			}

			return $user_info;
		}

		return false;
	}

	static public function GetMagInfo($mag_id = NULL, $mac = NULL, $get_ChannelIDS = false, $getBouquetInfo = false, $get_cons = false)
	{
		if (empty($mag_id)) {
			self::$ipTV_db->query("SELECT * FROM `mag_devices` WHERE `mac` = '%s'", base64_encode($mac));
		}
		else {
			self::$ipTV_db->query("SELECT * FROM `mag_devices` WHERE `mag_id` = '%d'", $mag_id);
		}

		if (0 < self::$ipTV_db->num_rows()) {
			$maginfo = array();
			$maginfo["mag_device"] = self::$ipTV_db->get_row();
			$maginfo["mag_device"]["mac"] = base64_decode($maginfo["mag_device"]["mac"]);
			$maginfo["mag_device"]["ver"] = base64_decode($maginfo["mag_device"]["ver"]);
			$maginfo["mag_device"]["device_id"] = base64_decode($maginfo["mag_device"]["device_id"]);
			$maginfo["mag_device"]["device_id2"] = base64_decode($maginfo["mag_device"]["device_id2"]);
			$maginfo["mag_device"]["hw_version"] = base64_decode($maginfo["mag_device"]["hw_version"]);
			$maginfo["user_info"] = array();

			if ($user_info = self::GetUserInfo($maginfo["mag_device"]["user_id"], NULL, NULL, $get_ChannelIDS, $getBouquetInfo, $get_cons)) {
				$maginfo["user_info"] = $user_info;
			}

			$maginfo["pair_line_info"] = array();

			if (!empty($maginfo["user_info"])) {
				$maginfo["pair_line_info"] = array();

				if (!is_null($maginfo["user_info"]["pair_id"])) {
					if ($user_info = self::GetUserInfo($maginfo["user_info"]["pair_id"], NULL, NULL, $get_ChannelIDS, $getBouquetInfo, $get_cons)) {
						$maginfo["pair_line_info"] = $user_info;
					}
				}
			}

			return $maginfo;
		}

		return false;
	}

	static public function CloseLastCon($user_id)
	{
		self::$ipTV_db->query("SELECT activity_id,server_id,pid FROM `user_activity_now` WHERE `user_id` = '%d' ORDER BY activity_id DESC LIMIT 1", $user_id);

		if (0 < self::$ipTV_db->num_rows()) {
			$info = self::$ipTV_db->get_row();
			Servers::RunCommandServer($info["server_id"], "kill -9 {$info["pid"]}");
			self::CloseAndTransfer($info["activity_id"]);
			return true;
		}

		return false;
	}
    
    static public function GetContainers()
    {
		self::$ipTV_db->query("SELECT * FROM `movie_containers`;");
		return self::$ipTV_db->get_rows();
    }
    
    static public function GetStream($vod_id)
    {
		self::$ipTV_db->query("SELECT * FROM `streams_sys` WHERE `stream_id` = %s;", $vod_id);
		return self::$ipTV_db->get_row();
    }
    
    static public function GetMovieDetails($vod_id)
    {
		self::$ipTV_db->query("SELECT * FROM `streams` WHERE `id` = %s;", $vod_id);
		return self::$ipTV_db->get_row();
    }

	static public function GetChannelsByBouquet($bouquet_ids)
	{
		if (!is_array($bouquet_ids) || empty($bouquet_ids)) {
			return array();
		}

		$bouquet_ids = array_map("intval", $bouquet_ids);
		$bouquet_channels_ids = array();
		self::$ipTV_db->query("SELECT bouquet_channels FROM `bouquets` WHERE `id` IN (" . implode(",", $bouquet_ids) . ")");

		foreach (self::$ipTV_db->get_rows() as $row ) {
			$bouquet_channels_ids = array_merge($bouquet_channels_ids, json_decode($row["bouquet_channels"], true));
		}

		$bouquet_channels_ids = array_unique($bouquet_channels_ids);
		sort($bouquet_channels_ids);
		self::$ipTV_db->query("SELECT * FROM `streams` WHERE `id` IN (" . implode(",", $bouquet_channels_ids) . ") ORDER BY `stream_display_name` ASC");
		return self::$ipTV_db->get_rows();
	}

	static public function MAGLog($MAG_ID, $action)
	{
		if (!is_numeric($MAG_ID) || empty($MAG_ID)) {
			$MAG_ID = "NULL";
		}

		self::$ipTV_db->query("INSERT INTO `mag_logs` (`mag_id`,`action`) VALUES(%s,'%s')", $MAG_ID, $action);
	}

	static public function ClientLog($stream_id, $userid, $action, $userip, $data = "")
	{
		$user_agent = (!empty($_SERVER["HTTP_USER_AGENT"]) ? htmlentities($_SERVER["HTTP_USER_AGENT"]) : "");
		$query_string = (empty($_SERVER["QUERY_STRING"]) ? "" : $_SERVER["QUERY_STRING"]);
		$data = array("user_id" => $userid, "stream_id" => $stream_id, "action" => $action, "query_string" => htmlentities($_SERVER["QUERY_STRING"]), "user_agent" => $user_agent, "user_ip" => $userip, "time" => time(), "extra_data" => $data);
		file_put_contents(TMP_DIR . "client_request.log", base64_encode(json_encode($data)) . "\n", FILE_APPEND);
	}

	static public function ClientConnected()
	{
		if ((connection_status() != CONNECTION_NORMAL) || connection_aborted()) {
			return false;
		}

		return true;
	}

	static public function GetSegmentsOfPlaylist($playlist, $prebuffer = 0)
	{
		if (file_exists($playlist)) {
			$source = file_get_contents($playlist);

			if (preg_match_all("/(.*?).ts/", $source, $matches)) {
				if (0 < $prebuffer) {
					$total_segs = intval($prebuffer / 10);
					return array_slice($matches[0], -$total_segs);
				}

				return $matches[0];
			}
		}

		return false;
	}

	static public function GeneratePlayListWithAuthentication($m3u8_playlist, $username = "", $password = "", $streamID)
	{
		if (file_exists($m3u8_playlist)) {
			$source = file_get_contents($m3u8_playlist);

			if (preg_match_all("/(.*?)\.ts/", $source, $matches)) {
				foreach ($matches[0] as $match ) {
					$source = str_replace($match, "http://{$_SERVER["HTTP_HOST"]}{$_SERVER["SCRIPT_NAME"]}?extension=m3u8&username=$username&password=$password&stream=$streamID&type=hls&segment=$match", $source);
				}

				return $source;
			}

			return false;
		}
	}

	static public function CheckGlobalBlockUA($user_agent)
	{
		$user_agent = self::$ipTV_db->escape($user_agent);
		self::$ipTV_db->simple_query("SELECT * FROM `blocked_user_agents` WHERE (exact_match = 1 AND user_agent = '$user_agent') OR (exact_match = 0 AND INSTR('$user_agent',user_agent) > 0)");

		if (0 < self::$ipTV_db->num_rows()) {
			$info = self::$ipTV_db->get_row();
			self::$ipTV_db->query("UPDATE `blocked_user_agents` SET `attempts_blocked` = `attempts_blocked`+1 WHERE `id` = '%d'", $info["id"]);
			exit();
		}
	}

	static public function ps_running($pid, $exe)
	{
		if (empty($pid)) {
			return false;
		}

		if (file_exists("/proc/" . $pid) && is_readable("/proc/" . $pid . "/exe") && (basename(readlink("/proc/" . $pid . "/exe")) == basename($exe))) {
			return true;
		}

		return false;
	}

	static public function ShowVideo($is_restreamer = 0, $video_id_setting, $video_path_id)
	{
		if (($is_restreamer == 0) && (ipTV_lib::$settings[$video_id_setting] == 1)) {
			header("Content-Type: video/mp2t");
			readfile(ipTV_lib::$settings[$video_path_id]);
		}

		exit();
	}

	static public function CloseConnection($activity_id)
	{
		self::$ipTV_db->query("SELECT * FROM `user_activity_now` WHERE `activity_id` = '%d'", $activity_id);

		if (0 < self::$ipTV_db->num_rows()) {
			$info = self::$ipTV_db->get_row();

			if (!is_null($info["pid"])) {
				Servers::RunCommandServer($info["server_id"], "kill -9 " . $info["pid"]);
				self::CloseAndTransfer($activity_id);
			}
		}
	}

	static public function CloseAndTransfer($activity_id)
	{
		if (empty($activity_id)) {
			return false;
		}

		if (!is_array($activity_id)) {
			$activity_id = array(intval($activity_id));
		}

		foreach ($activity_id as $id ) {
			self::$ipTV_db->query("INSERT INTO `user_activity` SELECT NULL,`user_id`,`stream_id`,`server_id`,`user_agent`,`user_ip`,`container`,NULL,`date_start`,'" . time() . "',`geoip_country_code`,`isp`,`external_device`,`divergence`,NULL,NULL FROM `user_activity_now` WHERE `activity_id` = '%d'", $id);
			self::$ipTV_db->query("DELETE FROM `user_activity_now` WHERE `activity_id` = '%d'", $id);
		}
	}

	static public function CloseAllConnectionsByUser($user_id)
	{
		self::$ipTV_db->query("SELECT * FROM `user_activity_now` WHERE `user_id` = '%d'", $user_id);

		if (0 < self::$ipTV_db->num_rows()) {
			$rows = self::$ipTV_db->get_rows();
			$activities = array();
			$ids = array();

			foreach ($rows as $row ) {
				if (empty($activities[$row["server_id"]])) {
					$activities[$row["server_id"]] = array();
				}

				$activities[$row["server_id"]][] = $row["pid"];
				$ids[] = $row["activity_id"];
			}

			foreach ($activities as $server_id => $pid ) {
				$command = "kill -9 " . implode(" ", $pid);
				Servers::RunCommandServer($server_id, $command);
			}

			self::CloseAndTransfer($ids);
		}
	}

	static public function CloseAllConnectionsByServer($server_id)
	{
		self::$ipTV_db->query("SELECT * FROM `user_activity_now` WHERE `server_id` = '%d'", $server_id);

		if (0 < self::$ipTV_db->num_rows()) {
			$rows = self::$ipTV_db->get_rows();
			$pids = array();
			$ids = array();

			foreach ($rows as $row ) {
				$pids[] = $row["pid"];
				$ids[] = $row["activity_id"];
			}

			$command = "kill -9 " . implode(" ", $pids);
			Servers::RunCommandServer($server_id, $command);
			self::CloseAndTransfer($ids);
		}
	}

	static public function IsValidStream($playlist, $pid)
	{
		return self::ps_running($pid, FFMPEG_PATH) && file_exists($playlist);
	}

	static public function getUserIP()
	{
		foreach (array("REMOTE_ADDR", "HTTP_INCAP_CLIENT_IP", "HTTP_CF_CONNECTING_IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED") as $key ) {
			if (array_key_exists($key, $_SERVER) === true) {
				foreach (explode(",", $_SERVER[$key]) as $IPaddress ) {
					$IPaddress = trim($IPaddress);

					if (filter_var($IPaddress, FILTER_VALIDATE_IP) !== false) {
						return $IPaddress;
					}
				}
			}
		}
	}

	static public function GetStreamBitrate($type, $path, $force_duration = NULL)
	{
		$birrate = 0;

		if (!file_exists($path)) {
			return $bitrate;
		}

		switch ($type) {
		case "movie":
			if (!is_null($force_duration)) {
				sscanf($force_duration, "%d:%d:%d", $hours, $minutes, $seconds);
				$time_seconds = (isset($seconds) ? ($hours * 3600) + ($minutes * 60) + $seconds : ($hours * 60) + $minutes);
				$bitrate = round((filesize($path) * 0.0080000000000000002) / $time_seconds);
			}

			break;

		case "live":
			$fp = fopen($path, "r");
			$bitrates = array();

			while (!feof($fp)) {
				$line = trim(fgets($fp));

				if (stristr($line, "EXTINF")) {
					list($trash, $seconds) = explode(":", $line);
					$seconds = rtrim($seconds, ",");
					$segment_file = trim(fgets($fp));

					if (!file_exists(dirname($path) . "/" . $segment_file)) {
						break;
					}

					$segment_size_in_kilobits = filesize(dirname($path) . "/" . $segment_file) * 0.0080000000000000002;
					$bitrates[] = $segment_size_in_kilobits / $seconds;

					if (count($bitrates) == ipTV_lib::$settings["client_prebuffer"] / 2) {
						break;
					}
				}
			}

			fclose($fp);
			$bitrate = (0 < count($bitrates) ? round(array_sum($bitrates) / count($bitrates)) : 0);
			break;
		}

		return $bitrate;
	}
}

class Servers
{
	static public function RunCommandServer($serverIDS, $cmd, $type = "array")
	{
		$output = array();

		if (!is_array($serverIDS)) {
			$serverIDS = array(intval($serverIDS));
		}

		if (empty($cmd)) {
			foreach ($serverIDS as $server_id ) {
				$output[$server_id] = "";
			}

			return $output;
		}

		foreach ($serverIDS as $server_id ) {
			if ($server_id == SERVER_ID) {
				exec($cmd, $return);
				$output[$server_id] = ($type == "array" ? $return : implode("\n", $return));
				continue;
			}

			if (!array_key_exists($server_id, ipTV_lib::$StreamingServers)) {
				continue;
			}

			$response = self::ServerSideRequest($server_id, ipTV_lib::$StreamingServers[$server_id]["api_url_ip"] . "&action=runCMD", array("command" => $cmd));

			if ($response) {
				$result = json_decode($response, true);
				$output[$server_id] = ($type == "array" ? $result : implode("\n", $result));
			}
			else {
				$output[$server_id] = false;
			}
		}

		return $output;
	}

	static public function ServerSideRequest($server_id, $URL, $PostData = array(), $force = false)
	{
		if ($force) {
			$status_ok = array(1, 4);

			if (!in_array(ipTV_lib::$StreamingServers[$server_id]["status"], $status_ok)) {
				return false;
			}
		}

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $URL);
		curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0) Gecko/20100101 Firefox/9.0");
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 7);
		curl_setopt($ch, CURLOPT_TIMEOUT, 7);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

		if (!empty($PostData)) {
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($PostData));
		}

		$output = curl_exec($ch);
		@curl_close($ch);
		return $output;
	}
}

$_LANG = array("allowed_countries_server" => "Select the Countries where this server will accept connections from in priority", "enable_geoip" => "Enable GeoIP Location Load Balancing", "server_geoip_help" => "If enabled, this server will  accept connections from the selected countries below in priority.", "flood_apply_clients" => "Apply Flood Rules to Normal Clients", "flood_apply_restreamers" => "Apply Flood Rules to Restreamers", "flood_apply_clients_help" => "If you tick yes, your flood rules will affect your normal clients if they are trying to bypass them", "flood_apply_restreamers_help" => "If you tick yes, your flood rules will affected your restreamers if they are trying to bypass them", "select_archive_server" => "Select the Server to Save the Recordings In", "select_archive_server_help" => "Select the Server you want the archive of this stream to be made in. Please note that the server you will select must restream this stream otherwise your tv archive settings wont be saved.", "tv_archive" => "TV Archive", "tv_archive_days" => "Number of Days to keep recording this stream", "tv_archive_days_help" => "Set the total number of days you want this stream to be recorded and to be available as archive. Entering 0 will disable the tv archive for this stream", "no_series_specified" => "No Series Number was specified but the VOD is in a subcategory", "new_radio" => "Add New Radio", "manage_radio" => "Manage Radios", "direct_source_help" => "This stream will not be restreamed and the stream URL will be used instead.", "direct_source" => "Use Direct Source & don't restream it", "direct" => "Direct", "url" => "URL", "manage_archive" => "Manage Archive", "archive_duration" => "Archive Duration", "actions" => "Actions", "flood_seconds" => "Request Frequency in Seconds", "flood_max_attempts" => "Flood Attempts Limit", "flood_max_attempts_help" => "The user IP will be banned if he makes X total attempts in a row to bypass the flood limits.", "flood_seconds_help" => "Indicates the number of period(in seconds) in which the next request should be made AFTER. If new request is made within this period, it's +1 evil request. If the user reaches the Flood Limit (above) with evil requests, it's +1 Attempt", "start_movie" => "Start Encoding", "mismatch" => "MisMatch", "restart_movie" => "ReStart Encoding", "stop_movie" => "Stop Movie Encoding", "servers" => "Servers", "preparing" => "Preparing", "partial_working" => "Partial Working", "needs_encode" => "Needs Encode", "series_exists" => "Series Number for that category exists", "series_no_help" => "Here you can specify the Number of the Series this VOD belongs to. You can only specify series number in SubCategories. Series Must equal or greater than 1 and must not exists in the database for that SubCategory", "series_no" => "This VOD Series Number Is", "is_parent" => "Parent Category", "category_parent" => "Category Parent ( VOD )", "uncategorized" => "Uncategorized", "wrong_ssh" => "Wrong SSH info", "fast_reload" => "Fast Reload", "warning_main" => "WARNING. Main Server {ip} is not responding", "main_server_offline" => "WARNING: Your Main Server appear to be offline so you can not continue. Below you can add Other Main Server Details to install the Xtream Codes IPTV Panel in.<br /><b>Doing This, will result in DATA LOSS in case you don't have a backup</b>", "license_expire" => "License is about to expire soon. Every function will be disabled after the expiration date", "ok" => "OK", "health" => "Health", "css_layout" => "CSS Theme", "main_server_fail" => "The last Main Server Installation has failed. Please contact the Support Team. You can try again importing the same or another server", "main_server_prepare" => "Your Main Server is being prepared Now. Please wait...", "add_main_server" => "Add Your Main Server", "add_main_server_desc" => "Seems like you haven't set a MAIN Server yet. Below simply specify the SSH Information of your server that you want to be as your MAIN. The main Server is the server where your Database will be located.<br />Compatible With Ubuntu 13.x, 14.x , 15.x , Debian 7.x & CentOS 7.x", "main_mysql_root" => "Specify the existing MySQL Root password from your Main Server. If you don't have a MySQL Server installed yet, please choose one now and the installation script will use that", "your_server" => "Your Streaming Server", "reseller_dns" => "Reseller DNS", "restart_http" => "Restart HTTP Streams Automatically", "restart_http_desc" => "If you set this to yes, system will restart http streams automatically when there is a connection drop or stream problem. If you set this to no, the system checker will run the stream again after ~1 minute. Automatically restart may break the backup channel function and you may notice a small lag/loop when an instant restart takes place", "latency" => "Latency", "file_not_writeable" => "File {file} is not writeable. Please fix it by running: chmod 777 {file}", "security_settings" => "Security Settings", "flood_limit" => "Flood Limit", "flood_limit_desc" => "The script checks for flood attack every 5 seconds. The Flood limit is the Maximum number of requests that a Single IP can do EVERY 5 seconds before it gets blocked. You can anytime see the blocked IPs under Block IP/CIDR Section. Enter 0 To disable DDos security check", "flood_ips_exclude" => "Exclude IPs (Seperate by comma)", "flood_ips_exclude_desc" => "The script will not check the following IPs and will not be blocked", "you" => "you", "staff" => "Staff", "from" => "from", "today" => "Today", "yesterday" => "Yesterday", "last_week" => "Last Week", "staff_reply" => "Staff Reply", "viewed" => "Viewed", "customer_reply" => "Customer Reply", "ticket_system" => "Tickets Support", "add_new_reply" => "Add Reply", "create_support_request" => "Create Support Ticket", "ticket_title" => "Ticket Title", "message" => "Message", "manage_tickets" => "Manage Tickets", "tprofiles" => "Transcoding Profiles", "transcode_settings" => "Transcode Settings", "tprofile_name" => "Profile Name", "edit_tprofile" => "Edit Transcoding Profile", "select_tprofile" => "Select Transcode Profile", "create_channel_pick" => "You can select as many videos as you want. You will be able to add more videos later and change the order of them", "no_tprofile" => "No Transcode", "select_tprofile_create" => "In order to make your own channel , all your videos have to be in the same output format (eg. codec, frame rate, width, height, aspect). For this reason you have to specify a transcoding profile. Please choose wisely.", "tprofiles_no" => "You need to have at least one Transcode Profile in Order to create your own Channel. This is needed, because when you combining multiple videos together, they have to use all the same transcoding attributes/options/codecs.", "tprofile_n_exists" => "Transcoding Profile Does not exists", "custom_tprofile" => "Custom Transcoding Options", "transcoding_p_exists" => "Transcoding Profile with the same name already exists", "transcoding_p_missing" => "Transcoding Profile Name is missing", "transcode_placeholder" => "My Transcode Profile...", "created_ch_bad" => "Bad Sources", "add_more_videos" => "Add More Videos In your Channel", "beta" => "BETA", "auto_backup_desc" => "If you enable this service, the panel will automatically create online secured backups every day which are strongly encoded and password protected with a password that you can specify above<br /> Bellow you will find the list of all available backup files (if there are any) and with the load button you can restore the backup on your server in seconds.<br/>For any reason if you want a manual backup, you can press the Secure Backup Now button.", "auto_backup_settings" => "Secure Online Auto Backup Settings", "auto_backup_enable" => "Enable Online Auto Backup", "auto_backup" => "Secure Automatic Online Backup", "backup_wrong_pass" => "Wrong Password Of Backup File", "backup_date" => "Backup Date", "server_ip" => "Server IP", "backup_size" => "Backup Size", "backup_load" => "Use Backup", "backup_list" => "Secure Online Backup List", "auto_backup_pass" => "Password For Secure Online Backups", "auto_backup_now" => "Secure Online Backup Now", "add_more_videos_desc" => "You can add more videos to your channel any time you want. Your videos will be transcoded again with the transcoding profile you have selected. You will be able to edit the order of your videos after the import", "delete_tprofile" => "You are about to delete a transcoding profile. All your Streams that are being transcoded using this profile, will loose their transcoding settings. Are you sure you want to continue?", "add_new_tprofile" => "Add New Transcoding Profile", "convert_from_ez" => "Convert EZserver To Xtream-Codes", "ez_port" => "EZServer Admin Panel Port", "create_in_progress" => "Edit is disabled until your old settings in this channel take place", "stream_move_up" => "Stream Move Up", "stream_move_down" => "Stream Move Down", "vod_move_up" => "Vod Move Up", "create_channel_edit" => "You edited the channel. Now you have to wait until your changes take place. (If you made added new videos or made a new order)", "create_channel_in_progress" => "The channel is in progress, you can't edit it at the moment. Please wait few minutes", "video_move_up" => "Video Move Up", "video_move_down" => "Video Move Down", "server_is_down" => "Your Server \"{server_name}\" is DOWN!", "video_delete" => "Video Delete", "vod_move_down" => "Vod Move Down", "disk_full" => "WARNING: The partition assigned to {partition} is almost full. You need to free up some disk space otherwise the whole panel will malfunction! This error will disappear when free space is available.", "ez_ip" => "EZServer Admin Panel IP", "crate_channel_main_load" => "You can't remove the server from balacing in which you first made this channel", "ez_user" => "EZServer Admin Username(Default: root)", "gen_pts" => "Generate PTS", "create_channel_order" => "Videos Order of your channel", "gen_pts_desc" => "Let the FFmpeg to generate the PTS (presentation timestamp) for you to achieve better synchronization with the stream codecs. In some streams(in unstables) may cause de-sync. Disable it only if the output video is not as the source", "ez_pass" => "EZserver Administration Password", "ez_auth_failed" => "EZServer Authentication Failed", "transfer" => "Transfer", "convert_from_ez_desc" => "This tool will help you to transfer all your Streams/Users/Bouquets from your EZServer to this xtream codes panel. All users will be transfered along with their bouquets and expire dates. Users will be able to open connections to Xtream Codes panel with the SAME OUTPUT LINK as EZserver, so there is no need to inform them and update their links. Everything will be converted except VOD.", "migrate" => "Migrate To Xtream-Codes", "wrong_captcha" => "Wrong Captcha Provided", "profile" => "Profile", "manage_profile" => "Manage profile", "password_changed" => "Password changed", "password_invalid" => "Your old password is wrong", "change_password" => "Change your password", "new_password" => "New password", "old_password" => "Old password", "new_password_confirm" => "Confirm new password", "selected_line_is_already_paired" => "The selected line is already paired with another device!", "start_all_movies" => "Encode all movies", "encode_all_warn" => "Please note! If you have many movies to prepare WITH TRANSCODING, this process will consume a LOT of CPU Power. If you haven't select to transcode your movies then it is safe to use it. Are you sure you want to continue?", "stop_encode_all_warn" => "Any ACTIVE encoding process will be stopped. You will have to start again to re-encode your movies. Are you sure you want to continue?", "stop_all_movies" => "Stop all movies encoding", "logout" => "Logout", "save_orders" => "Save order", "edit_orders" => "Edit order", "your_orders" => "Your streams & VOD order", "mag_details" => "MAG details", "search_mag" => "Search MAG device", "is_isplock" => "Lock user to his ISP", "zend_loader_missing" => "Zend Guard loader is missing. Please run this command from SSH as ROOT (COPY AND PASTE EVERYTHING) and refresh this page:<br /><br />wget -qO \"/home/xtreamcodes/iptv_xtream_codes/php/lib/php/extensions/no-debug-non-zts-20131226/ZendGuardLoader.so\" \"http://xtream-codes.com/ZendGuardLoader.so\" && echo 'zend_extension=ZendGuardLoader.so' >> /home/xtreamcodes/iptv_xtream_codes/php/lib/php.ini && echo 'zend_loader.disable_licensing=0' >> /home/xtreamcodes/iptv_xtream_codes/php/lib/php.ini && pkill -9 php && /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm", "enable_lines" => "Enable all lines of registered user", "disable_lines" => "Disable all lines of registered user", "reg_user_enabled_lines" => "All the lines of the user are enabled!", "reg_user_disabled_lines" => "All the lines of the user are disabled!", "external" => "External", "stalker_channel_mismatch" => "STALKER channel mismatch", "stalker_ip_mismatch" => "STALKER IP MISMATCH", "stalker_key_expired" => "STALKER key expired", "stalker_decrypt_failed" => "STALKER KEY DECRYPT FAILED!", "is_isplock_desc" => "This will pair the line with the ISP provider on the first connection and will not be able to see from other isp!", "domain_name" => "Domain name", "isp_reseted" => "The ISP lock is reseted!", "isp" => "ISP", "disallow_empty_user_agents" => "Disallow connections with empty user agent", "disallow_empty_user_agents_desc" => "Tick yes to disallow connections from users with empty user agent", "requires_addon" => "Requires Addon", "empty_ua" => "No user agent", "different_isp_connected" => "Users connected from different ISPs while the ISP-lock feature was enabled", "main_isp" => "Main ISP", "reset_isp_all" => "Reset all ISPs", "is_stalker" => "This line will be used in STALKER Portal", "is_stalker_desc" => "Check this option if you are going to use this line in your Stalker Portal so users can connect to it. Setting a line as stalker means it will have unlimited connections by default and no expire date. Users that will connect through it  will appear with their MAC Address Under Connection logs instead of username. You MUST use the MPEG-TS format for stalker portal. HLS is disabled.", "max_connections_desc" => "Enter how many concurrent connections the users should have. Entering 0 means unlimited connections. For normal clients the best is 1 and for restreamers you should set the connections equal to the total number of channels you had assigned to the line. It does NOT affect the HLS output. HLS output is limited to 1 connection only unless you put this value to zero (0) which means unlimited.", "reset_isp_all_desc" => "Reset all ISPs restrictions for all your users.", "block_svp" => "Disallow Servers/VPN/Proxies from watching channels!", "block_svp_desc" => "This setting will prevent users connected from Servers/VPN/Proxies to open connection to your Servers. No matter what you will select, the log about that action will be written below. Please note that Restreamers (Is Restreamer = Yes under Add/Edit User) are not affected by this setting and no log will be written.", "diff_isp" => "Different ISP", "update_run_background" => "Update will now be executed in background. You may notice small service-interruptions during this time.", "mag_enabled" => "MAG Device Enabled", "country_disallow" => "COUNTRY DISALLOW", "mag_disabled" => "MAG Device Disabled", "mag_kicked" => "MAG Device Kicked", "show_in_red_online" => "Show In Red The User Connections, Based On Total Time Online", "connection_settings" => "Connection Settings", "show_in_red_online_desc" => "This setting will help you identify the users who are resharing your streams without your permissions or to catch the idle users. The value you will specify here must be given in hours. It does not affect restreamers. Enter 0 to disable it.", "creator" => "creator", "user_auto_kick_hours" => "Auto kick users if they are online for x hours", "user_auto_kick_hours_desc" => "The system will auto kick the user's connection(s) that are online for more than X hours. This setting does not affect restreamers. Enter 0 to disable.", "lock_lines_package" => "Enable ISP-lock for the existing lines", "tries" => "Total Tries", "clear_reg_user_log" => "Delete line activity log", "clear_reg_user_log_desc" => "Delete line activity log table. You need to provide your MySQL root password in order to execute this task!", "reg_userlog" => "Line Activity Log", "isp_lock_failed" => "Connected from another ISP", "reshare_purcashe" => "You need to purchase or enable \"Detect Reshares Addon\" in order to be functional", "reimport_load_queries" => "Flush Permissions", "reimport_load_queries_desc" => "If you have transferred your \"Main Server\" to another server or if you re-installed your panel from a backup, you need to run this tool to allow your \"Load Balancer(s)\" servers to connect to your Database. It will also re-write the configuration file again with your new IP of your \"Main Server\". You need to run this tool only once.", "allowed_ips_desc" => "Allowed IPs to access the Admin Live/VOD Streaming. In general your Load Balancer servers are using this module to transfer the stream data to other servers. You are using this module too when you press the example output at the Manage Streams. By default all administrators have access to this function. However, you can specify more IPs (separated by comma) in case you need to do something else. By default you shouldn't allow more IPs.", "allowed_ips_admin" => "Allowed IPs to access admin streaming", "stream_all" => "Stream all the codecs found on the video", "stream_all_desc" => "This option will stream all codecs from your stream. Some streams have more than one audio/video/subtitles channels. If you want to stream them all as one, then you need to enable this option.", "server_deleted" => "Server deleted successfully!", "server_delete_warn" => "WARNING!!! All files, movies and streams will be deleted from the server! This action can not be reverted once is done! Are you sure you want to continue? WARNING!!!", "dashboard" => "Dashboard", "custom_ffmpeg" => "Custom FFmpeg command", "custom_ffmpeg_desc" => "In this field you can write your own custom FFmpeg command. Please note that this command will be placed after the input and before the output. If the command you will specify here is about to do changes in the output video or audio, it may require to transcode the stream. In this case, you have to use and change at least the Video/Audio Codecs using the transcoding attributes below. The custom FFmpeg command will only be used by the server(s) that take the stream from the Source.", "server_deleted_couldn_con" => "Server deleted from the database! However, IPTV Panel was unable to connect to the remote SSH to completely delete the files. Please do it manually by executing the following commands:<br />rm -rf /home/xtreamcodes<br />crontab -u xtreamcodes -e<br />and delete everything that contain ffmpeg, php-fpm, nginx<br />same for: /etc/init.d/rc.local<br />then execute the command: <br />apt-get update && apt-get autoremove && apt-get autopurge<br />\n", "new_stream" => "Add New Stream", "transcode_stream_desc" => "Sometimes, in order to make a stream compatible with most devices, it must be transcoded. Please note that the transcode will only be applied to the server(s) that take the stream directly from the source, all other servers attached to the transcoding server will not transcode the stream.", "force_server" => "Force the user to connect to", "force_server_desc" => "This user will be redirected all the time to your selected server or if set the default option, the software will dispatch the user to less used server.", "dont_force" => "Don't force. Use Default.", "manage_streams" => "Manage Streams", "is_restreamer" => "Is Restreamer", "is_restreamer_desc" => "This option does NOT prevent someone from restreaming your streams, it is only for you to know and identify the restreamers.", "custom_sid" => "Custom Channel SID", "custom_sid_error" => "Your SID syntax is NOT ok! Please correct it.", "custom_sid_desc" => "Here you can specify the SID of the channel in order to work with the epg on the enigma2 devices. You have to specify the code with the ':' but without the first number, 1 or 4097 . Example: if we have this code:  '1:0:1:13f:157c:13e:820000:0:0:0:2097' then you have to add on this field:  ':0:1:13f:157c:13e:820000:0:0:0:'", "extend_line" => "Extend Line", "you_have_no_lines" => "There are no lines attached to your account!", "streams" => "Live Streams", "edit_category" => "Edit Category", "category_nexists" => "This category id does not exist!", "edit_group" => "Edit Group", "group_edited" => "Group Edited", "edited" => "Edit", "pass_mkv_container" => "Pass Stream Data From MKV Container", "group_exists" => "A group with the same name already exists", "select_group" => "Select a Group to Edit", "xtream_port_help" => "Please choose an HTTP Broadcast Port. Installation will not make any check to see if the port is open, so the script might failed if the port is in use. You will be able to change the HTTP Port later.", "group_id_nexists" => "The selected group does not exists!", "no_packages_found_group" => "No packages found for your group! Please contact your administrator.", "select_package" => "Select package to assign to this line", "mass_edit" => "Mass edit streams", "trials" => "Trials", "server_offline_edit" => "It appears that this server is offline. You can't edit this server at the moment.", "per_day" => "Per day", "bytes_sent_mbps" => "Output flow(mbps)", "bytes_received_mbps" => "Input flow(mbps)", "you_cant_generate_trials" => "The trial accounts generated have been reach! Access denied. Please contact your administrator.", "per_month" => "Per month", "you_have_no_mag" => "You have no MAG devices under your account", "per" => "Per", "extend_mag" => "Extend MAG", "user_blocked" => "User blocked!", "stream_tools" => "Stream tools", "user_extended" => "User extended and package applied", "close" => "Close", "domain_exists" => "The domain exists. Your servers MUST have a different domain names. If you don't have a domain name for this server you can leave it empty and the server IP will be used instead", "total_allowed_gen_trials" => "Number of uses allowed", "username_device" => "Username/Device", "mag_device_edited" => "MAG Device Edited", "dont_pair" => "Don't Pair", "sshpass_protected" => "SSH Password Protected. Leave it blank to remain the same. Change only if SSH password has changed", "sent_mag" => "SENT OUT", "group_removed" => "Selected Group completely removed!", "account_information" => "Account Information", "mag_mac_exists" => "This MAC Address already exists as device. Please look at the Manage Devices page", "mag_devices" => "MAG Devices", "edit_mag" => "Edit MAG device settings", "user_dis_exit" => "Output format disallowed for this user!", "pair_line_max_cons" => "Paired Line. Maximum connections exceeded.", "mag_deleted" => "MAG Device Deleted", "event_type" => "Event Type", "pending" => "PENDING", "editor" => "Editor", "mag_reset" => "Reset MAG device", "mag_blocked" => "MAG Device Blocked", "mag_nexists" => "MAG Device ID Does not exists", "mag_device_added" => "MAG Device Added", "wrong_mac" => "Wrong MAC Address Provided", "add_new_mag" => "Add New MAG Device", "manage_mag" => "Manage MAG Devices", "user_unblocked" => "User unblocked", "close_portal" => "Close Portal", "update_done" => "Update Done. No need to re-boot", "reload_portal" => "Reload Portal", "reboot" => "Reboot", "send_message" => "Send Message", "mac_address" => "Device MAC Address", "pair_with" => "Pair This MAG Device With a Line", "pair_with_desc" => "You can pair this MAG device with an exiting user line. Attention, the MAG device can not be connected if the line is online and vice versa. Leave blank not to pair.", "event_actions" => "Actions", "main" => "Main", "desktop_mode" => "Desktop Mode:", "trial_use" => "Trial", "search_channels" => "Search Channels...", "unblock_block" => "Unblock/Block", "you_are_watching" => "You Are Watching", "account_info" => "Account Info", "enable_disable" => "Enable/Disable", "official_use" => "Official Use", "line_is_unlimited" => "Line is Unlimited! For that reason you cannot extend it", "reseller_only" => "(Reseller Only)", "leave_it_blank_gen" => "Leave it blank to Auto Generate Random Chars", "mysql_root_pass_wrong" => "MySQL Root Password provided is wrong.", "mysql_root_pass" => "MySQL Root Password", "not_enough_credits" => "You don't have enough credits to purchase this package", "mysql_root_pass_help" => "IPTV Panel needs your MySQL Root Password from your MAIN SERVER to add some commands, which will let your remote server to access the database. Your MySQL Root password will not be saved in the database. You need to enter it every time when you want to add a new server", "type" => "Type", "current_load_balance" => "Your Current Streaming Flow", "draw_new_load_balance_chart" => "Draw Stream Data Flow", "movie_container_desc" => "Select a movie container.", "force_channel" => "Force Channel to Play", "admin_notes" => "Admin Notes", "reseller_notes" => "Reseller Notes", "message_sent" => "Message Sent. It will appear on TV Screen in about {s} seconds", "event_sent" => "Event Sent. Event will take place in about {s} seconds", "event_sent_unknown" => "Event Sent. Event will take place as soon as the device goes online", "message_sent_unknown" => "Message Sent. It will be displayed on the TV Screen as soon as the device goes online", "movie_container" => "Select Movie Container Format", "stream_name" => "Stream name", "new_reguser" => "Register New User", "reseted_nok" => "Error reseting MAG data", "reseted_ok" => "MAG data successfully reset", "dont_edit_same" => "If you want your load balancing settings to remain the same, don't draw new chart", "manage_regusers" => "Manage Registered Users", "user_confirm_msg" => "User must confirm the message", "reboot_after_ok" => "Reboot Device After Confirming (above option must be yes)", "play_channel" => "Play Channel", "force_channel_play" => "Change to this channel", "manage_events" => "Manage Events", "message" => "Message", "login_logs" => "Login Logs", "new_package" => "New Package", "manage_packages" => "Manage Packages", "new_package_options" => "New package options", "edit_package" => "Edit Package", "delete_package_confirm" => "Are you sure you want to delete this package?", "delete_package" => "Delete This Package", "credits_price" => "Credits price", "line_type" => "Select Line Type", "package_contains" => "Package contains", "resellers" => "Resellers", "trial_package" => "Trial Package", "official_package" => "Official Package", "package_type" => "Package Type", "package_name" => "Package Name", "duration" => "Duration", "close_server_cons" => "Drop all client connections on this server", "uncompleted_server" => "Uncompleted Server", "manage_groups" => "Manage Group Members", "reg_users" => "Registered Users", "is_reseller" => "Is reseller", "all_cons_dropped" => "All connections dropped from this server", "select_timezone" => "Select Timezone", "manage_epg" => "Manage EPG", "edit_epg" => "Edit EPG", "subtitles_help" => "Selected subtitles file will be embed in the Video Codec. That means your movie to be playable must be transcoded to another video format. IPTV Panel will automatically select the H.264 Codec after you select your subtitles. If IPTV Panel was unable to encode the movie using your subtitles, try again to encode them with UTF-8 Charset settings", "stream_icon" => "Stream icon URL", "user_stats" => "User Stats", "con_info" => "Connection Info", "streams_stats" => "Stream Stats", "line_exists" => "Line with the same Username already exists. You can't have duplicate username", "epg_options" => "EPG Options", "subtitles_location" => "Subtitle Location", "select_epg_edit" => "Select EPG to edit", "select_epg_source" => "Select EPG Source", "start_movie_request_sent_all" => "Start signal was sent for all movies. Please wait", "stop_movie_request_sent_all" => "Stop signal was sent for all in-progress movies. You may need to refresh the page to see the actual status as this is not an instant event.", "select_epg_channel_id" => "Select EPG Channel ID", "select_epg_lang" => "Select EPG Language", "movie_deleted" => "Movie Deleted", "epg_id_nexists" => "EPG ID does not exist", "server_id_nexists" => "Server ID does not exist", "select_server_edit" => "Select Server to Edit", "select_servers_load" => "Select Load Balancer Servers", "load_balancer_desc" => "Select the Servers to use them as Restreamers. Your clients will only be allowed to connect to those.", "stream_output_desc" => "Select the stream formats you want to allow for the CLIENT to use. It is recommended to keep mpegts always on. Select HLS only if you have compatibility problems. HLS Output is limited to 1 connection unless you have chosen from below unlimited connections.", "new_acc" => "Create New Line", "epg_exists" => "EPG with the same name already exists", "epg_edited" => "EPG Edited.", "add_new_epg" => "Add a New EPG Source", "epg_name" => "EPG Name", "epg_source" => "EPG Source File", "analyze_ip" => "Analyze the IP", "create_mag" => "Create MAG", "only_mag" => "Only For MAG Devices", "mag_package_alert" => "You can't change this option as you had already selected that you want this package only for MAG Devices. Deselect the option below to change that", "can_gen_mag" => "Reseller Can Create MAG Devices", "can_only_mag" => "Only MAG Devices Can be created by this package", "analyze_ip_desc" => "This tool will run \"whois\" on the selected IP Address", "not_valid_epg" => "Not a valid EPG File", "delete_confirm_epg" => "All your saved EPG in channels will be deleted too. There is no undo!", "epg_imported" => "EPG Imported with success", "error_epg_exists" => "EPG already exists (Name or source). Please choose another", "epg_lang" => "Your Desired EPG Language (Must exists in the XML EPG File)", "node" => "Node", "import_stream" => "Import", "import_streams_file" => "Upload m3u/m3u8 File", "not_on_air_enable" => "Show A Video When a Stream is not working", "not_on_air_desc" => "If your stream is not playable due to Source Down or for any other reason , you may want to show a small video to your client with explanations.", "not_on_air_settings" => "Not on Air - Video Settings", "you_are_banned_settings" => "Settings for Line Banned", "banned_video_enable" => "Show A Video When a line is banned", "banned_video_desc" => "Enable this if you have banned a user line and you want to display a message on your user's TV Screen", "expired_video_settings" => "Settings for User Line Expired", "expired_video_enable" => "Show A Video when an Expired User is trying to access a Stream", "expired_video_desc" => "Show a video if a user line is expired", "video_path" => "Specify The FULL URL Path to your Video", "video_path_desc" => "Specify the Full URL to your Video. The Video must be in the MPEGTS format.", "server_connections" => "Server Connections", "video_settings" => "Video Settings", "server" => "Server", "manage_accs" => "Manage Lines", "removed" => "Removed", "remove" => "Remove", "codecs" => "Codecs", "view_output" => "View Output", "stream_accs" => "Streaming Lines", "group_name" => "Group Name", "copyrights_remove" => "Do you wish to Remove the Xtream-Codes Copyrights?", "no_addon_purchase" => "If you enable this setting and YOU haven't purchased this addon from Xtream-Codes Website your LICENSE will become INVALID!", "copyrights_text" => "Enter Your Own Copyrights", "dont_change" => "Do not Change", "update_bins" => "Update Bins", "update_bins_background" => "A script is running in background. That will check your version and will perform an update if is needed. Your streams may disconnect in the next 5 mins", "update_bins_desc" => "Update your FFmpeg/FFprobe to the latest version. You can achieve much better performance and stream stability by upgrading to the latest version. Run this tool only if you see a warning on the dashboard.", "ffmpeg_outdated" => "Your FFmpeg/FFprobe Version is outdated. You can update your bins by going to the Tools->Update Bins", "output_format" => "Stream Output Format", "server_down" => "Server Down", "group_color" => "Group Color", "edit_server" => "Edit Server", "panel_error_log" => "Panel Error Log", "connections" => "Connections", "client_request_log" => "Client Request Log", "create_channels" => "Create Channels", "create_new_channel" => "Create Channel", "channel_name" => "Channel Name", "channel_settings" => "Channel Settings", "manage_created_channels" => "Manage Created Channels", "log_message" => "Log Message", "connection_sq" => "Client Speed", "select_xtream_port" => "HTTP BroadCast Port", "owner" => "Owner", "preset" => "Preset", "video_profile" => "Video Profile", "transcode_stream" => "Transcode Stream", "html_code" => "HTML Hex Code Color", "banned" => "BANNED", "access_admin_cp" => "This Group Can Access the Admin CP", "group_banned" => "This is a banned group", "total_users" => "Total Users", "add_new_source_backup" => "Add stream source [Backup]", "do_it" => "Do it", "remove_argument" => "Remove argument", "bouquets" => "Bouquets", "security" => "Security plug-ins", "block_ips" => "Block IP/CIDR", "ip" => "IP", "tool_name" => "Tool Name", "description" => "Description", "clear_login_logs" => "Clear login logs", "clear_login_logs_desc" => "This action will delete all the login logs from the database. MySQL root password is required for this operation!", "clear_panel_logs" => "Clear panel logs", "clear_panel_logs_desc" => "This action will delete all the panel logs from the database", "clear_client_request_logs" => "Clear client request logs", "clear_client_request_logs_desc" => "This action will delete all the client request logs from the database.", "run_tool" => "Execute", "update_panel" => "Software Update", "download_update" => "Download update", "block_ua" => "Block user agent", "files_writeable" => "Please Write This Command in SSH and the download button will appear: \"chmod -R 777\"", "change_log" => "Changes in this version", "blocked_attempts" => "Blocked Attempts", "block_ua_explain" => "Blocked User Agents will not be able to open connections to your server for watching the streams", "enter_ua" => "Write the User Agent you want to block", "use_exact_match" => "Use Exact Match", "date_blocked" => "Date Blocked", "flush_rules" => "Flush iptables rules", "preset_desc" => "A preset is a collection of options that will provide a certain encoding speed to compression ratio. A slower preset will provide better compression (compression is quality per filesize). This means that, for example, if you target a certain file size or constant bit rate, you will achieve better quality with a slower preset. Similarly, for constant quality encoding, you will simply save bitrate by choosing a slower preset.", "unblock_ip" => "Are you sure you want to unblock this IP?", "block_ip" => "Block IP / CIDR", "profile_desc" => "If you want your videos to have highest compatibility with target devices (older iOS versions or all Android devices)", "create_new_group" => "Create New Group", "user_agents" => "Block User Agent", "unblock_ua" => "Are you sure you want to unblock this User Agent?", "user_agent" => "User Agent", "confirm" => "Are you sure?", "user_agent_block_list" => "User Agent Block List", "block_ip_explain" => "IP will be blocked from iptables", "edit_bouquet" => "Edit Bouquet", "add_bouquet" => "Add New Bouquet", "blocked_ips" => "Blocked IPs List", "package_deleted" => "Package deleted", "package_edited" => "Package edited!", "edit_package_options" => "Edit Package Options", "delete_bouquet" => "Delete Bouquet", "manage_bouquet" => "Manage Bouquets", "user_details" => "Provide User Details", "package_nexists" => "Package does not exist", "logs" => "Logs", "yes" => "Yes", "no" => "No", "select_live_streams" => "Select Live Streams", "restart_streams_after" => "Restart Streams After Editing", "connection_logs" => "Client Connection Logs", "general_settings" => "General Settings", "add_block_ip" => "Write the IP or CIDR Range you want to block", "server_name" => "Server Name", "network_interface" => "Network Interface", "logo_url" => "Your Logo URL", "live_pass" => "Live Streaming Pass", "registration_settings" => "Registration Settings", "allow_registrations" => "Allow Registrations", "confirmation_email" => "Send Confirmation E-mail After Registration", "allow_multiple_accs" => "Allow Users to Register Multiple Accounts", "username_strlen_setting" => "Max Username Lengths During Registration", "username_alpha_setting" => "Allow Only AlphaNumeric In Usernames", "bouquet_name" => "Enigma2 Bouquet Name", "mail_settings" => "Mail Settings", "database" => "Database Manager", "task" => "Task Manager", "system" => "System", "tools" => "Tools", "total_lines" => "Total Streaming Lines", "connected" => "Connected", "kill_all" => "Kill All Active Connections", "kill_all_desc" => "This tool will kill all the active connections from all of your servers. It means that every user will be disconnected from your server and the status will become offline.", "remove_expired_desc" => "This tool will delete all your expired lines. Please select which type of lines you want to delete. DOES NOT delete MAG devices which are expired.", "remove_expired" => "Remove Expired Lines", "update" => "Software update", "verified" => "Verified", "delete_closed" => "Delete closed connections", "delete_closed_desc" => "This tool will delete all closed connections. Please note that when you delete a connection you loose some of your total bandwidth stats.", "delete_closed_based" => "Delete closed connections logs based on the online time", "delete_closed_based_desc" => "This tool will delete all closed connections logs based on the time in seconds they were online.<br />The value entered means that the system will delete the connections with a total time spent online less end X seconds.<br />It's very useful when you want to clear all Zero Time Connections", "server_connections_deleted" => "Server connections deleted", "delete_sconnections" => "Delete closed server connections", "delete_sconnections_desc" => "This tool will delete all finished server connections entries from your database", "member_area" => "Members Area", "edit_user" => "Edit User", "closed" => "Closed", "new_answer" => "New Reply!", "open" => "Open", "ticket_is_closed" => "Ticket is closed. You can not reply to closed tickets", "ticket_history" => "Ticket History", "administrator" => "Administrator", "ticket_nexists" => "This ticket does not exists", "ticket_not_own" => "This ticket is not yours!", "member_area_desc" => "In this page you can see and manage your licenses", "xtream_codes" => "Xtream-Codes", "last_reply" => "Last Reply", "close_ticket" => "Are you sure you want to close this ticket? Closed tickets can not receive any answer", "member_not_exists" => "Selected member does not exists!", "delete_group" => "WARNING: Deleting a group will delete ALL registered users including their lines that belongs to this group. Are you sure you want to continue? There is NO undo!", "user_added" => "User added", "complete_fields" => "Please fill out all the fields", "add_bouquet_first" => "You haven't made any Bouquet so you can't process. Please go to Add New Bouquet and select the streams you want to create one.", "username" => "Username", "unknown_error" => "Unknown error occurred.", "password" => "Password", "access_denied" => "Access Denied", "run_per_mins" => "Run per mins", "assign_to" => "Assign the Account To a Member", "enable_cronjob" => "Enable Cronjob", "info" => "Info", "disable_cronjob" => "Disable Cronjob", "line_nexists" => "Streaming Line ID does not exists!", "allowed_ips" => "Allowed IPs to use this account", "allowed_user_agents" => "Allowed User Agents to use this account", "enter_ip" => "Enter IP...", "load_balancer_settings" => "Load Balancer Settings", "split_clients" => "Split clients", "query_string" => "Query String", "split_equal" => "Equally to each server", "split_wait" => "After full server load is reached", "split_clients_help" => "Splitting your clients equally to each server is the best option as it will keep all your servers loads at reasonable levels.", "not_in_bouquet" => "Not allowed", "user_disable" => "USER DISABLED", "user_expired" => "USER EXPIRED", "auth_failed" => "AUTH FAILED", "user_ip_banned" => "IP BANNED", "user_ua_banned" => "User Agent banned", "trial_lines_chkbox" => "Trial lines", "official_lines_chkbox" => "Official Lines", "trial_line" => "This Line is a Trial Line", "trial_line_desc" => "This line will be inserted into your system as a trial line. Trial lines have the same feature as normal lines, however they will appear in your system with different colour. As admin, you can control from below the features that a trial line will have", "enter_useragent" => "Enter User Agent...", "add_ua" => "Add this User Agent to allowed list", "add_ip" => "Add this IP to allowed list", "remove_selected" => "Remove selected", "allow_all_ips" => "Allow all IPs (default)", "allow_all_ua" => "Allow all User Agents (default)", "select_line_mng" => "Please select a Line to edit from the Manage Lines Page", "def_all_allowed" => "Default all allowed", "max_connections" => "Max Allowed Connections", "same_time" => "At the same time", "expire_date" => "Expire Date", "package_added" => "Package Added", "is_trial" => "Is trial", "is_official" => "Is official", "trial_info" => "Trial Info", "official_info" => "Official Info", "bouquet_name1" => "Bouquet Name", "credits" => "Credits", "create_packages_first" => "No Reseller packages found", "package_exists" => "Package with the same name already exists", "select_bouquet" => "Select Bouquet(s) for this user", "select_bouquet_packages" => "Select Bouquets you want to assigned for this package", "trial_credits" => "Trial credits cost", "select_resellers_groups" => "Select the Groups to whom you want to have this package visible", "official_credits" => "Official credits cost", "select_bouquet_page" => "Please select a Bouquet to edit from the Manage Bouquets page", "notes" => "Notes", "hours" => "Hours", "days" => "Days", "start_recording" => "Start Recording Process", "stop_recording" => "Stop Recording Process", "epg_program" => "EPG Program", "timeshift_delete" => "Warning. You are about to delete all the recordings for this stream. Are you sure you want to continue?", "programs" => "Programs", "official_duration" => "Official duration", "trial_duration" => "Trial duration", "create_new_package" => "Create new package", "months" => "Months", "years" => "Years", "unlimited" => "Unlimited", "expired" => "EXPIRED", "status" => "Status", "download" => "Download", "online" => "Online", "bouquet" => "Bouquet", "ls_channel" => "Channel", "options" => "Options", "loading" => "Loading content... Please wait!", "no_logs" => "No logs were found", "login" => "Log In", "register" => "Register", "online_clients" => "Online Clients", "start_stream" => "Start/Restart stream on the selected server", "start_stream_all" => "Global (re)start stream", "stop_stream" => "Stop streams in selected server", "stop_stream_all" => "Global streams stop", "edit_stream" => "Edit Stream", "delete_stream" => "Delete Stream", "delete_streams" => "Delete streams", "source_down" => "Source Down", "restarting" => "Restarting", "fetch_options" => "Fetching Options", "live_streaming_test" => "Live Streaming Test", "audio_codec" => "Audio Codec", "video_codec" => "Video Codec", "start_all" => "(Re)Start All Streams", "start_running" => "(Re)Start Running Streams", "stop_all" => "Stop All Streams", "forgot" => "Forgot your Password?", "forgot_pass" => "Forgot password?", "email" => "E-Mail", "statistics" => "Statistics", "confirm_password" => "Confirm Password", "submit" => "Submit", "edit_reguser" => "Edit Registered User", "reg_user_edited" => "Registered user edited successfully", "user_edited" => "Streaming line edited successfully", "group_not_exists" => "Selected Group Doesn't Exists", "email_in_use" => "E-mail address already in use", "username_exists" => "User with this username already exists!", "select_reguser" => "Please select a registered user from manage registered user", "reset" => "Complete this if you want to reset", "member_group" => "Group Members", "new_regadded" => "New registered user added", "dif_pass_conf" => "The password does not match the confirmation password", "min_password" => "The minimum length of the password is {length} chars", "username_strlen" => "The maximum allowed chars in username is {length}", "username_alpha" => "Username must contain only alphanumeric chars", "invalid_email" => "Email address is not in a valid format!", "registration_closed" => "Registration is closed!", "ip_in_use" => "You can't register second account", "register_confirm" => "Registration successful. Please check your emails to verify your account", "register_ok" => "Registration successful. You can now login with your credentials", "wrong_uinfo" => "Login Failed", "email_msg" => "Edit email messages", "user_is_disabled" => "User is disabled", "user_is_banned" => "User is banned", "save_settings" => "Save settings", "delete_line" => "Are you sure you want to delete this line?", "stream_options" => "Stream options", "stream_source" => "Enter live stream URL", "email_verify_edit" => "Edit email verification message", "email_forgot_edit" => "Edit forgotten password message", "action_done" => "Action done", "smtp_host" => "SMTP Host", "smtp_username" => "SMTP Username", "smtp_password" => "SMTP Password", "smtp_port" => "SMTP Port", "mail_from" => "Enter the email address which you want the emails to come from", "use_remote_smtp" => "Use remote SMTP server", "smtp_encryption" => "SMTP Encryption", "smtp_from_name" => "SMTP from name", "account_verified" => "Account verified. Please login below!", "no_email_found" => "No user found with this email address", "new_pass_sent" => "Your new password has been sent to your email", "email_new_pass_edit" => "Edit new password message", "forgot_email_sent" => "Please check your email!", "restore_database" => "Restore database", "user_kicked" => "User kicked", "user_enabled" => "User enabled", "user_disabled" => "User disabled", "date" => "Date", "manage_my_lines" => "Manage my streaming lines", "kick_user" => "Kick User", "view_user_activity" => "View User activity", "no_sql_extension" => "No valid extension found in the file you uploaded. Supported extensions: *.sql , *.gz", "restore_done" => "Database is being restored in the background. Data will be imported automatically in a few seconds depending on your total database size", "queries_executed" => "Queries executed successfully", "upload_size" => "The uploaded file exceeds the upload_max_filesize directive in php.ini", "partially_upload" => "The uploaded file was only partially uploaded", "temp_missing" => "Missing a temporary folder", "no_write" => "Failed to write file to disk", "run_queries_title" => "Run SQL query (for advanced users only)", "paste_queries" => "Paste your SQL queries", "run_queries" => "Run queries", "total_open_cons" => "Total open connections", "total_online_users" => "Total online users", "total_running_streams" => "Active streams", "clients_countries" => "Your clients' connections by country", "total_bandwidth" => "Total bandWidth served", "system_uptime" => "System uptime", "view_connections" => "View connections", "country" => "Country", "connection" => "Connection", "flag" => "Flag", "channel" => "Channel", "bandwidth" => "Bandwidth", "total_time_online" => "Total time online", "date_started" => "Date started", "date_end" => "Date end", "show_all_cons" => "Show all connections", "show_closed_cons" => "Show closed connections", "show_open_cons" => "Show open connections", "closed" => "Closed", "opened" => "Opened", "closed_unex" => "Closed unexpectedly", "kill_con" => "Are you sure you want to kill the connection and delete this activity?", "waiting" => "Waiting...", "analyzing" => "Analyzing", "forced_allowed_countries" => "Override General Country Restriction", "forced_allowed_countries_desc" => "This will override (bypass) the general country restriction on the general settings.", "bad_system_os" => "OS unsupported", "streaming_settings" => "Streaming and client settings", "allowed_countries_desc" => "Allow Connections from Specific Countries (Will be overridden if for a user you select a specific country)", "allowed_countries" => "Allow connections from these countries", "allowed_countries_server_in" => "Allow connections from these countries in priority", "stream_max_analyze" => "Stream analyze duration", "stream_max_analyze_help" => "Specify how many microseconds are analyzed to probe the input. A higher value will enable detecting more accurate information, but will increase latency. Default is 5,000,000 microseconds = 5 seconds.", "image" => "Movie Image", "plot" => "Plot", "cast" => "Cast", "director" => "Director", "rating" => "Rating", "pick" => "Pick", "select_movies_channel" => "Select your movies in the wanted order", "genre" => "Genre", "channel_crated" => "Your channel has been added to the database. You have to wait some time for your channel to be prepared. But don't worry, relax. When it's ready you will be able to see it from the Manage Created Channels page", "create_some_channels" => "No created channels were found but... you can create one any time :)", "subtitles" => "Subtitles", "releasedate" => "Release date", "load_balancer_movie_desc" => "Select the Servers you want the movie to be saved to. Load balancing will be used.", "client_prebuffer" => "Client prebuffer techniques", "client_prebuffer_time" => "Prebuffer In seconds", "time_watching" => "Time watching", "movie_propeties" => "Movie Properties", "client_prebuffer_time_help" => "This setting will help you to change the zapping time and to avoid any possible lags when your clients will watch streams. This value means how many video data in seconds will be sent to the user when he connect to the stream. Larger value means larger prebuffer data for the client. It also means that user will get X seconds live stream earlier.", "preparing" => "Preparing...", "delete_activity" => "Delete Activity", "select_movies_to_import" => "Select Movies To Import", "kill_connection" => "Kill Connection", "click_restart_stream" => "Stream edited! You must restart the stream to take the new settings. Click {HERE} to restart the stream! (for all servers)", "imdb_movie_details" => "Fetch movie details from IMDB, if can be found", "imdb_movie_details_help" => "IPTV Panel will try to guess the movie name from the filename. If the guessed filename exists in the IMDB records IPTV Panel will get all the information associated with the movie.", "bouquet_added" => "Bouquet Added", "bouquet_exists" => "Bouquet with the same name already exists", "make_streams_first" => "You can't create a bouquet since you don't have any stream. Please create some streams", "add_some_streams" => "You don't have any stream. Please create some streams.", "stream_exists" => "Stream with that name ({stream_name}) already exists. Please choose another", "stream_added" => "Stream added ({stream_name})", "task_enabled" => "Task Enabled", "task_disabled" => "Task Disabled", "disabled" => "DISABLED", "ip_blocked" => "IP Blocked!", "findusers_ip" => "Find users based on their IP", "no_users_found" => "No users found with this IP", "findusers_ip_desc" => "This tool will help you to find all streaming lines, with username & password, that use this IP to connect to your servers.", "invalid_ip" => "This IP/CIDR is not valid!", "ip_exists" => "This IP is already blocked!", "ip_unblocked" => "IP Unblocked!", "enabled" => "Enabled", "delete_user" => "Delete User", "remote_backup_now" => "Remote Backup Now", "password_hidden" => "Password is hidden for security reasons", "create_bouquets_first" => "You haven't made any bouquet. Please go, create a bouquet and after assign streams", "bouquet_deleted" => "Bouquet Deleted", "settings_saved" => "Settings Saved", "connection_killed" => "Connection Killed", "connection_deleted" => "Connection closed and activity deleted!", "no_connections_found" => "No connections were found", "bouquet_edited" => "Bouquet edited", "source" => "Source", "backup_restore_confirm" => "Are you sure you want to restore this backup file? Your may loose your current data if they are not included in this backup", "transcode_movie" => "Transcode Movie", "dest" => "Destination", "view_server_connecitons" => "View Server Connections", "stream_id_nexists" => "Stream ID Does not exists", "bouquet_id_nexists" => "Bouquet ID Does not exists!", "user_id_nexists" => "User ID Does not exists!", "user_id" => "User ID", "delete_reg_user" => "Are you sure you want to delete this user? All of his lines will be deleted as well", "select_stream_edit" => "Please select a stream to edit from the Manage Streams page", "select_movie_edit" => "Please select a movie to edit from the Manage Movies page", "unknown" => "Unknown", "run_cmd_server" => "Run commands in remote server", "server_status1" => "Server is busy at the moment. Please wait until you can rebuilt it", "new_version_out" => "New version of IPTV Panel is released!", "valid" => "VALID", "failed" => "FAILED", "data" => "Data", "latest_ver" => "You have the latest version!", "tmp_nwriteable" => "Temp directory {DIR} is not writable. Please use \"chmod\". You can't use the restore function", "zip_missing" => "ZipArchive class is missing. Install the required extension", "stream_edited" => "Stream edited", "group_added" => "Group added", "cant_delete_group" => "Can't delete this group.", "userlines_deleted" => "Users and lines deleted!", "no_regusers_found" => "No registrered users found.", "user_agent_blocked" => "User Agent blocked", "user_agent_unblocked" => "User Agent unblocked", "no_streaming_lines_found" => "No streaming lines found", "show_me_stats" => "Show me stats", "search_line" => "Search Line", "stats_for_user" => "Statistics For {user} with password {pass}", "user_deleted" => "User Deleted", "create_stream_first_mass" => "You can't Mass Edit Streams since you don't have any stream created!", "all_connections_killed" => "All Connections are Killed", "closed_connections_deleted" => "All Closed Connections are Deleted", "no_restart_found" => "Streams Edited but you didn't restart them. You must restart the streams with the new changes. You can do this from the Manage Streams Page", "read_native" => "Read Input Source in Native Frames", "read_native_desc" => "If you set this to NO, IPTV Panel will read the input as fast as possible. Any process should be executed faster, however your CPU usage may increase, especially when you are transcoding. It is recommended to enable this if you are transcoding, otherwise set this to NO.", "confirm_encode_action" => "WARNING: You are about to change the encoding(start/stop) of this movie in the selected server. Are you sure you want to continue? If the movie Source does not exists, you might loose your movie completely", "restart_movie_conf" => "WARNING! This will re encode your movie in all your servers. There is no reason to do so unless something gone bad in your previous encoding or if there is a mismatch between your movies. The movie will be deleted and will be re encoded. If the source do not exists anymore the process will fail.", "movie_length" => "Movie length", "movie_stop_request_sent" => "Movie stop/delete request sent!", "please_wait" => "Please wait while loading...", "movie_location" => "Movie location", "delete_movie_warn" => "WARNING! Your movie will be COMPLETELY DELETED from all of your servers!! Are you sure you want to continue?!", "import_one_stream" => "Import one stream", "import_multiple_streams" => "Import Multiple Streams", "location_remote" => "Remote in other server", "import_movies" => "Import Multiple Movies", "movies_location" => "Select your Movies Location to Import", "movie_source_folder" => "Movies Folder / Directory Listing", "categories" => "Stream Categories", "manage_categories" => "Manage Categories", "new_category" => "New Category", "category_name" => "Category Name", "total_streams" => "Total Streams", "delete_category" => "Delete Category", "delete_category_confirm" => "The existing movies attached to this category will be moved to no category. Please confirm the action!", "category_type" => "Category Type", "category_added" => "Category Added!", "category_exists" => "The category name already exists", "category_deleted" => "Category deleted", "dont_use_category" => "Don't Use Category", "uptime_stream" => "Uptime", "add_server" => "Add New Server", "mysql_root_wrong" => "MySQL Root Password provided is wrong", "streaming_servers" => "Streaming Servers", "manage_servers" => "Manage Servers", "server_ip" => "Server IP", "ssh_port" => "SSH Port", "ssh_password" => "SSH password", "client_slots" => "Clients Slots", "total_clients" => "Total Allowed Clients", "new_server_added" => "A new server has been added. This server is being prepared at the moment. The main server will now install(in the background) all the required packages to the remote server automatically. Still, you can continue working on the main server web.", "ssh_no_auth" => "Authentication failed! Please make sure the information (IP, ssh port, password for root) are valid and try again", "ssh_no_auth_main" => "Authentication failed! Please make sure the information (IP, ssh port, password for root) of your MAIN Server are valid and try again", "server_edited" => "Server Edited", "probesize" => "ProbeSize", "probesize_desc" => "Set probing size in bytes, i.e. the size of the data to analyze for getting stream information. A higher value will allow to detect more information in case it is dispersed into the stream, but will increase latency. Must be an integer not less than 32. 5000000 is the default.", "server_no_edit" => "Server can not be edited. SSH Details are wrong", "server_exists" => "a Server with the Same IP Already Exists", "add_some_servers" => "You haven't attached any external server to the main site so far. If needed and the license permits it, one can be added by accessing the option 'Add New Server' in main menu.", "delete_server" => "Delete server", "server_os" => "Operating System", "delete" => "Delete", "enable_all" => "Enable all", "disable_all" => "Disable all", "reload" => "Reload", "enable_isp_lock_all" => "Enable ISP lock to all line accounts", "enable_isp_lock_all_desc" => "Please note that if you haven't purchase this add-on, the \"ISP lock\" will not have effect.", "remake_server" => "Remake Server", "edit" => "Edit", "sent" => "Sent", "on" => "on", "remove_mag_events" => "Remove MAG Events", "remove_mag_events_desc" => "This tool will help you to mass delete the MAG Events. If you decide to remove the PENDING event will means the event won't reach the receiver", "port_already_listen" => "Can't change HTTP Broadcast port. The specified port is already in use or port given is lower than 80! Please choose a different port and try again.", "prepare_movie" => "Prepare in all the servers", "view" => "View", "popular_streams" => "Most popular streams", "movie_start_request_sent" => "Movie start request sent. Please wait until the current running process will be fully completed.", "most_spent_time" => "Total time spent on each stream", "movie_added" => "The movie have been added. In order to prepare the movie on a server, please access the option 'Manage Movies' and select the current added movie.", "stream_start_request_sent" => "Start stream command sent", "stream_output" => "Select allowed output formats", "stream_output_package" => "Please select the output format(s) that the line account will be allowed to use", "stream_output_package_desc" => "Please note that the change does not affect MAG Devices. MAG Devices will be created with both HLS & MPEGTS.", "stream_deleted" => "Stream deleted successfully", "add_movies" => "No movies were found.", "devices_output" => "Select device default output method", "server_type" => "Server ISP/type", "not_exists" => "It doesn't exist!", "addons" => "Addons", "con_svp" => "Connected using proxy or from a data-center!", "reshare_deny" => "Detect VPN/proxies/servers & ISP lock", "users_connected_from_svp" => "Users connected from servers/VPN/proxies!", "catch_reshares" => "Detect VPN/proxies/servers & ISP lock", "enable_addon" => "Enable Addon", "information" => "Information", "domain_listen_ip" => "The domain name you entered does not listen to the Server IP", "catch_reshares_desc" => "This addon is useful if you want to detect the users that re-streaming or even re-sharing their lines with friends. <br /><br />                               <b>This addon adds 2 different security layers in your system:</b><br /><br />                                                             1. It detects the lines that are connected from Proxies/VPNs/Servers (table log below)<br />                                2. It locks each line to the first ISP that it is connected. You can reset it if you wish, under Manage lines )<br /><br />                                                                Please note that this addon is taking the logs from the Client Request Log section. If you empty these logs using a tool, you will loose all the stats (if any).<br />                                <br />                                                              <b>What do you need to get working this Addon:</b><br /><br />                                                             1. Purchase this Addon directly from our WHMCS (www.xtream-codes.com) and enable the Addon below.<br />                               2. Make sure that the cronjob \"<u>Client log import</u>\" under task manager is enabled<br />                               3. For ISP-Locking you need to enable the \"<u>Lock User to his ISP</u>\" Setting under Add/Edit Line (You can run also the tool below to enable for all users)<br /><br />                                                             <font color=\"red\">Remember to change the \"Is Restreamer\" setting of the line to reshare the stream otherwise it may be blocked by the filters of this Addon</font>                                                   ", "last_seen_channel" => "Last Seen Channel", "last_connection" => "Last Connection", "backup_optimize_background" => "Database will now be optimized in background. You may experience brief disruptions of service.", "remake_server_conf" => "IPTV Panel will reinstall all the required packages on this server. Are you sure you want to do this?", "import_server" => "From this page you can import another server and use it as a load balancer, as transcoding server or for anything you want. IPTV Panel will automatically connect to the server via SSH and will install all the required packages. IPTV Panel will try to connect using root as username. Please note that only Ubuntu & Debian x64 are supported. You can install one External Server for free. For more please contact the xtream-codes team and update your license.", "show_all_cat_mag" => "Show \"All\" Category in MAG Devices", "auto_restart_channel" => "Auto Restart Stream After X Hours", "vpn_ip" => "VPNs IP", "dont_override" => "Don't override", "vpn_ip_desc" => "Enter here the VPNs IP of your server, if it has one. This IP will be used to broadcast the Streams to your clients. If empty, the Server IP will be used instead", "auto_restart_channel_help" => "Cronjob will restart this channel after X hours. It is useful to restart the channels at least one time per day. You can set this to 0 (default), which means disabled.", "show_all_cat_mag_help" => "Select this if you want to show the category called <<All>>. This is the default for MAG devices. Please note that uncategorized streams only appears by default in <<All>> category. If you deselect this you have to be sure that all your streams have a category.", "stream_stopped" => "Stream(s) Stopped Successfully!", "movies" => "VOD (Video On Demand)", "new_movie" => "Add New Movie", "new_video" => "Add New Video", "manage_movies" => "Manage Movies", "movies_options" => "Movie Options", "movie_name" => "Movie Name", "movie_source" => "Movie Source", "movie_subtitles" => "Movie Subtitles", "delete_movie" => "Delete this movie", "in_progress" => "In Progress", "movie_edited" => "Movie edited. You may need to re-encode it if you change the transcode attributes or subtitles", "edit_movie" => "Edit Movie", "bad_movie" => "Bad Movie", "movie" => "Movie", "live" => "Live", "movie_id_nexists" => "Movie Does NOT exists", "select_streams" => "Select Streams / Movies", "live_streams_select" => "Select Live Streams", "movies_select" => "Select Movies", "your_bouquet" => "Your Bouquet", "streams_stoped_success" => "All streams stopped.", "streams_started" => "All Streams Started Successfully", "please_wait_ajax" => "Please wait for this process to be completed. It can take a while. Do not close this window !", "backup_database" => "Backup database", "bitrate" => "Bitrate", "transcoding" => "Transcoding", "next" => ">> Next", "previous" => ">> Previous", "last_updated" => "Last Updated", "never" => "Never", "mtr_missing" => "MTR Package is missing. Please install it by running the command \"apt-get install mtr\" from your SSH", "select_default_lang" => "Default Language", "more_than_1" => "You need to import more than one video files to create a channel. If you have only one video file then you can import it directly as a live stream.", "epg_force_reload" => "EPG Updated.", "total_epg_data" => "Total EPG data", "delete_subtitles" => "Delete Existing Subtitles", "delete_subtitles_help" => "In case your video file have subtitles on it, you may wish to remove them, so you can embed your own. Please note that this setting will not delete already embed subtitles. Embed subtitles are those that are hard coded into the video", "read_native_live" => "You should always read LIVE streams as non-native frames so the default should be the best. However if you are streaming static video files , for example movies, set this to YES otherwise the encoding process will be instant finished", "bin_not_exec" => "FFmpeg/FFprobe is not executable. Please contact us using tickets to fix that", "too_low_analyze" => "Your analyze stream duration is too low. You may notice strange behaviour of streams. You can increase this value under General Settings", "too_low_probesize" => "Your probesize value is too low. You may notice strange behaviour of streams. You can increase this value under General Settings", "combiner_not_executable" => "Your combiner.sh script is not executable. Please use \"chmod\" or contact us using tickets to fix that");
$_INFO = array();

if (file_exists(IPTV_PANEL_DIR . "config")) {
	$_INFO = json_decode(file_get_contents(IPTV_PANEL_DIR . "config"), true);
	define("SERVER_ID", $_INFO["server_id"]);
}
else {
	exit("no config found");
}

$ipTV_db = new ipTV_db($_INFO["db_user"], $_INFO["db_pass"], $_INFO["db_name"], $_INFO["host"]);
ipTV_lib::$ipTV_db = &$ipTV_db;
ipTV_Stream::$ipTV_db = &$ipTV_db;
ipTV_lib::init();
CheckFlood();
?>