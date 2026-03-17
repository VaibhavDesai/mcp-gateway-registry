-- capture_body.lua: Read request body and encode it in X-Body header for auth_request
local cjson = require "cjson"

-- Read the request body
ngx.req.read_body()
local body_data = ngx.req.get_body_data()

if body_data then
    -- Strip newlines to prevent breaking HTTP header format
    -- (JSON whitespace is insignificant per RFC 8259, so this is safe)
    local clean_body = body_data:gsub("[\r\n]+", " ")
    -- Set the X-Body header with the cleaned body data
    ngx.req.set_header("X-Body", clean_body)
    ngx.log(ngx.INFO, "Captured request body (" .. string.len(body_data) .. " bytes) for auth validation")

    -- Detect tools/list JSON-RPC method for response filtering
    -- Uses ngx.var (nginx variable) instead of ngx.ctx because auth_request
    -- subrequests reset ngx.ctx but preserve nginx variables
    local ok, parsed = pcall(cjson.decode, body_data)
    if ok and parsed and parsed.method == "tools/list" then
        ngx.var.is_tools_list = "1"
        ngx.log(ngx.INFO, "Detected tools/list request - will filter response")
    end
else
    ngx.log(ngx.INFO, "No request body found")
end
