---------
-- General utility functions.

local M = {}

--- Returns the `value` if not nil or empty, otherwise returns the
-- `default_value`.
function M.default (value, default_value)
  if value == nil or value == '' then
    return default_value
  end
  return value
end

--- Returns true if the `value` is nil, empty string or contains at least one
-- character other than space and tab. If the `value` is not nil and
-- string, then it's converted to string.
function M.is_blank (value)
  return value == nil or value == '' or tostring(value):find('^%s*$') ~= nil
end

--- Returns a new table containing the contents of tables `tab1` and `tab2`.
-- Entries with duplicate keys are overwritten with the values from `tab2`.
function M.merge (tab1, tab2)
  local tab3 = {}
  for k, v in pairs(tab1) do tab3[k] = v end
  for k, v in pairs(tab2) do tab3[k] = v end
  return tab3
end

--- Partial application.
-- Takes a function `func` and arguments, and returns a function *func2*.
-- When applied, *func2* returns the result of applying `func` to the arguments
-- provided initially followed by the arguments provided to *func2*.
--
-- @param func
-- @param ... Arguments to pass to the `func`.
-- @treturn func A partially applied function.
function M.partial (func, ...)
  local args1 = {...}

  return function(...)
    local args2 = {...}
    -- concat args1 and args2
    for i = 1, #args1 do table.insert(args2, i, args1[i]) end

    return func(unpack(args2))
  end
end

--- Returns value of the specified request's cookie.
--
-- @tparam string name The name of the cookie to get.
-- @treturn string A value of the specified cookie, or nil if doesn't exist.
function M.get_cookie (name)
  return ngx.var['cookie_'..name]
end

--- Formats HTTP cookie from the given arguments.
--
-- @tparam string name
-- @tparam string value
-- @tparam {[string]=string,...} attrs The cookie's attributes. Underscores in
--   the attribute name are implicitly replaced with dashes.
-- @treturn string A cookie string.
function M.format_cookie (name, value, attrs)
  local t = { name..'='..ngx.escape_uri(value) }
  for k, v in pairs(attrs) do
    k = k:gsub('_', '-')
    table.insert(t, v == true and k or k..'='..v)
  end
  return table.concat(t, ';')
end

return M