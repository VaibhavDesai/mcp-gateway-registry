-- filter_tools.lua: body_filter that removes disabled tools from tools/list responses
-- Uses ngx.var.is_tools_list (nginx variable set by capture_body.lua in rewrite phase)
-- nginx variables survive auth_request subrequests unlike ngx.ctx
local cjson = require "cjson"

-- Skip if this is not a tools/list request
if ngx.var.is_tools_list ~= "1" then
    return
end

-- Get the enabled tools list from the nginx $enabled_tools variable
-- This is a JSON array of enabled tool names set in the location block
local enabled_tools_json = ngx.var.enabled_tools
if not enabled_tools_json or enabled_tools_json == "" then
    -- No filtering configured for this server, pass through
    return
end

-- Buffer the response body across chunks
-- body_filter_by_lua is called per-chunk; we need the full body to parse JSON
-- ngx.ctx is safe here because body_filter runs after auth_request completes
local chunk = ngx.arg[1]
local eof = ngx.arg[2]

if not ngx.ctx.filter_buffer then
    ngx.ctx.filter_buffer = ""
end

ngx.ctx.filter_buffer = ngx.ctx.filter_buffer .. (chunk or "")

if not eof then
    -- Not the last chunk yet, suppress output and keep buffering
    ngx.arg[1] = ""
    return
end

-- Last chunk: process the full buffered response
local full_body = ngx.ctx.filter_buffer

-- Parse the enabled tools set
local ok_et, enabled_set = pcall(cjson.decode, enabled_tools_json)
if not ok_et or type(enabled_set) ~= "table" then
    ngx.log(ngx.WARN, "filter_tools: failed to parse enabled_tools, passing through")
    ngx.arg[1] = full_body
    return
end

-- Build a lookup set for O(1) checking
local enabled_lookup = {}
for _, name in ipairs(enabled_set) do
    enabled_lookup[name] = true
end

-- Try to parse as plain JSON first, then as SSE format
local resp = nil
local is_sse = false
local sse_prefix = ""
local sse_suffix = ""

local ok_body, parsed = pcall(cjson.decode, full_body)
if ok_body and type(parsed) == "table" then
    resp = parsed
else
    -- Try SSE format: extract JSON from "data:" lines
    -- SSE format example: "event: message\ndata: {json}\n\n"
    for line in full_body:gmatch("[^\r\n]+") do
        local data_json = line:match("^data:%s*(.+)")
        if data_json then
            local ok_sse, sse_parsed = pcall(cjson.decode, data_json)
            if ok_sse and type(sse_parsed) == "table" and sse_parsed.result then
                resp = sse_parsed
                is_sse = true
                -- Capture everything before and after the data line for reconstruction
                local data_start = full_body:find(data_json, 1, true)
                if data_start then
                    -- Find the "data: " prefix position
                    local line_start = full_body:sub(1, data_start - 1):match(".*()data:%s*$")
                    if not line_start then
                        -- Fallback: find "data: " just before the json
                        line_start = data_start - 6  -- "data: " is 6 chars
                        if line_start < 1 then line_start = 1 end
                    end
                end
                break
            end
        end
    end
end

if not resp then
    ngx.log(ngx.WARN, "filter_tools: could not parse response (first 200 chars): " .. full_body:sub(1, 200))
    ngx.arg[1] = full_body
    return
end

-- Filter tools in the result
if resp.result and resp.result.tools and type(resp.result.tools) == "table" then
    local filtered = {}
    local removed = 0
    for _, tool in ipairs(resp.result.tools) do
        if tool.name and enabled_lookup[tool.name] then
            table.insert(filtered, tool)
        else
            removed = removed + 1
        end
    end
    resp.result.tools = filtered
    ngx.log(ngx.INFO, "filter_tools: kept " .. #filtered .. " tools, removed " .. removed .. " disabled tools")

    -- Re-encode the JSON
    local ok_enc, new_json = pcall(cjson.encode, resp)
    if ok_enc then
        if is_sse then
            -- Reconstruct SSE frame with filtered JSON
            local new_body = "event: message\ndata: " .. new_json .. "\n\n"
            ngx.arg[1] = new_body
            ngx.header.content_length = #new_body
        else
            ngx.arg[1] = new_json
            ngx.header.content_length = #new_json
        end
    else
        ngx.log(ngx.ERR, "filter_tools: failed to re-encode response")
        ngx.arg[1] = full_body
    end
else
    -- Not a tools/list result format, pass through
    ngx.arg[1] = full_body
end
