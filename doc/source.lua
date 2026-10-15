-- Pandoc Lua filter: keep the build inside the doc directory. Accept an image only when every
-- file it can resolve to, symlinks followed, is in the doc directory, and refuse any raw content
-- (LaTeX, HTML) of the sources. It runs before the other filters, which may add raw content of their own.

-- Canonical path of an existing file, or nil
local function realpath(path)
  local ok, out = pcall(pandoc.pipe, "realpath", { "-e", "-q", "--", path }, "")
  if ok then
    return (out:gsub("\n$", ""))
  end
  return nil
end

local doc_dir = realpath(pandoc.path.directory(PANDOC_SCRIPT_FILE))

local function check_source(img)
  local src = img.src
  local refuse = function()
    error("Refusing the resource '" .. src .. "': use a file of the doc directory")
  end
  -- no URL, and no percent-encoding that the resource lookup could decode differently
  if not doc_dir or src == "" or src:find("%", 1, true) or src:match("^%a[%w+.-]*:") then
    refuse()
  end
  local found = false
  for _, dir in ipairs(PANDOC_STATE.resource_path) do
    local path = realpath(pandoc.path.join({ dir, src }))
    if path then
      if path:sub(1, #doc_dir + 1) ~= doc_dir .. "/" then
        refuse()
      end
      found = true
    end
  end
  if not found then
    refuse()
  end
end

local function refuse_raw(raw)
  error("Refusing raw " .. raw.format .. " content in the documentation sources")
end

return {
  {
    Image = check_source,
    RawBlock = refuse_raw,
    RawInline = refuse_raw,
  },
}
