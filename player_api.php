<?php
require "./includes/extend.php";

ini_set("memory_limit", -1);
if (!empty(ipTV_lib::$request["username"]) && !empty(ipTV_lib::$request["password"])) {
	$valid_actions = array("get_live_categories", "get_vod_categories", "get_live_streams", "get_short_epg", "get_simple_data_table", "get_vod_streams", "get_vod_info");
	$username = ipTV_lib::$request["username"];
	$password = ipTV_lib::$request["password"];
	$action = (!empty(ipTV_lib::$request["action"]) && in_array(ipTV_lib::$request["action"], $valid_actions) ? ipTV_lib::$request["action"] : "");
	$output = array();

	if ($result = ipTV_Stream::GetUserInfo(NULL, $username, $password, true, true, true)) {
		switch ($action) {
        
        case "get_live_categories":
            $categories = GetCategories("live");
            foreach ($categories as $category) {
                $output[] = Array("category_id" => $category["id"], "category_name" => $category["category_name"], "parent_id" => 0);
            }
            
            break;

        case "get_vod_categories":
            $categories = GetCategories("movie");
            foreach ($categories as $category) {
                $output[] = Array("category_id" => $category["id"], "category_name" => $category["category_name"], "parent_id" => 0);
            }
            
            break;

        case "get_live_streams":
            $streams = ipTV_Stream::GetChannelsByBouquet($result["bouquet"]);
            $i = 0;
            foreach ($streams as $stream) {
                $i ++;
                if ((((isset($_GET["category_id"])) && ($stream["category_id"] == $_GET["category_id"])) OR (!isset($_GET["category_id"]))) && ($stream["type"] == 1)) {
                    $output[] = Array("num" => $i, "name" => $stream["stream_display_name"], "stream_type" => "live", "stream_id" => $stream["id"], "stream_icon" => $stream["stream_icon"], "epg_channel_id" => $stream["channel_id"], "added" => $stream["added"], "category_id" => $stream["category_id"], "tv_archive" => 0, "direct_source" => "", "tv_archive_duration" => 0);
                }
            }
            break;

        case "get_vod_streams":
            $containers = Array();
            foreach (ipTV_Stream::GetContainers() as $container) {
                $containers[$container["container_id"]] = $container["container_extension"];
            }
            $streams = ipTV_Stream::GetChannelsByBouquet($result["bouquet"]);
            $i = 0;
            foreach ($streams as $stream) {
                $i ++;
                if ((((isset($_GET["category_id"])) && ($stream["category_id"] == $_GET["category_id"])) OR (!isset($_GET["category_id"]))) && ($stream["type"] > 1)) {
                    $movie_properties = json_decode($stream["movie_propeties"], True);
                    if (isset($movie_properties["rating"])) {
                        $rating = floatval($movie_properties["rating"]);
                        $rating_5 = ceil($rating / 2.0);
                    } else {
                        $rating = null;
                        $rating_5 = 0;
                    }
                    $output[] = Array("num" => $i, "name" => $stream["stream_display_name"], "stream_type" => "movie", "stream_id" => $stream["id"], "stream_icon" => $movie_properties["movie_image"], "added" => $stream["added"], "category_id" => $stream["category_id"], "direct_source" => "", "rating" => $rating, "rating_5based" => $rating_5, "custom_sid" => null, "container_extension" => $containers[$stream["target_container_id"]]);
                }
            }
            break;
            
        case "get_vod_info":
            $containers = Array();
            foreach (ipTV_Stream::GetContainers() as $container) {
                $containers[$container["container_id"]] = $container["container_extension"];
            }
            if (isset(ipTV_lib::$request["vod_id"])) {
                $vod = ipTV_Stream::GetMovieDetails(ipTV_lib::$request["vod_id"]);
                $stream = ipTV_Stream::GetStream(ipTV_lib::$request["vod_id"]);
                $movie_properties = json_decode($vod["movie_propeties"], True);
                if (isset($movie_properties["rating"])) {
                    $rating = floatval($movie_properties["rating"]);
                } else {
                    $rating = null;
                }
                $stream_info = $stream["stream_info"];
                $audio = Array(); $video = Array();
                $output["info"] = Array("imdb_id" => "", "movie_image" => $movie_properties["movie_image"], "genre" => $movie_properties["genre"], "plot" => $movie_properties["plot"], "cast" => $movie_properties["cast"], "director" => $movie_properties["director"], "rating" => $rating, "releasedate" => $movie_properties["releasedate"], "duration_secs" => $movie_properties["duration_secs"], "duration" => $movie_properties["duration"], "bitrate" => $stream["bitrate"], "kinopoisk_url" => "", "episode_run_time" => "", "youtube_trailer" => "", "actors" => $movie_properties["cast"], "name" => $vod["stream_display_name"], "name_o" => $vod["stream_display_name"], "cover_big" => $movie_properties["movie_image"], "description" => $movie_properties["plot"], "age" => "", "rating_mpaa" => "", "rating_count_kinopoisk" => 0, "country" => "", "backdrop_path" => [], "audio" => $audio, "video" => $video);
                $output["movie_data"] = Array("stream_id" => $vod["id"], "name" => $vod["stream_display_name"], "added" => $vod["added"], "category_id" => $vod["category_id"], "container_extension" => $containers[$vod["target_container_id"]], "custom_sid" => "", "direct_source" => "");
            }
            break;

		case "get_short_epg" || "get_simple_data_table":
			if (isset(ipTV_lib::$request["stream_id"])) {
				$stream_id = intval(ipTV_lib::$request["stream_id"]);
                if ($action == "get_simple_data_table") {
                    $limit = 1000;
                } else {
                    if (isset($_GET["limit"])) {
                        $limit = $_GET["limit"];
                    } else {
                        $limit = 4;
                    }
                }
				$EPGs = GetEPGStreamPlayer($stream_id, $limit);
                $return = Array();
                $i = 0;
                foreach ($EPGs as $EPG) {
                    $i ++;
                    if ($action == "get_simple_data_table") {
                        if ($i == 1) {
                            $EPG["now_playing"] = 1;
                        } else {
                            $EPG["now_playing"] = 0;
                        }
                        $EPG["has_archive"] = 0;
                    }
                    $EPG["title"] = base64_encode($EPG["title"]);
                    $EPG["description"] = base64_encode($EPG["description"]);
                    $EPG["start_timestamp"] = $EPG["start"];
                    $EPG["stop_timestamp"] = $EPG["end"];
                    $EPG["start"] = date("Y-m-d H:i:s", $EPG["start"]);
                    $EPG["end"] = date("Y-m-d H:i:s", $EPG["end"]);
                    $return[] = $EPG;
                }
				echo json_encode(Array("epg_listings" => $return));
				exit();
			}
			else {
				echo json_encode(array());
				exit();
			}
			break;

		default:
            $output["user_info"] = array();
			$url = (empty(ipTV_lib::$StreamingServers[SERVER_ID]["domain_name"]) ? ipTV_lib::$StreamingServers[SERVER_ID]["server_ip"] : ipTV_lib::$StreamingServers[SERVER_ID]["domain_name"]);
			$output["server_info"] = array("url" => $url, "port" => $_SERVER["SERVER_PORT"], "server_protocol" => "http", "timezone" => date_default_timezone_get(), "timestamp_now" => time(), "time_now" => date("Y-m-d H:i:s"), "rtmp_port" => "", "https_port" => "");
			$output["user_info"]["username"] = $result["username"];
			$output["user_info"]["password"] = $result["password"];
			$output["user_info"]["auth"] = 1;
            $output["user_info"]["message"] = "";

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
		}
	}
	else {
		$output["user_info"]["auth"] = 0;
	}
	echo json_encode($output);
}
?>
