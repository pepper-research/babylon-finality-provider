

latest-block:
	curl -X GET "https://rpc.celestia.nodestake.org/status" | jq '.result.sync_info.latest_block_height'