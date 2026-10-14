-- Pandoc Lua filter: keep the build inside the doc directory. Refuse the images given by
-- absolute path, parent directory or URL, and any raw content (LaTeX, HTML) of the sources.
-- It runs before the other filters, which may add raw content of their own.

local function check_source(src)
  if src:match("^/") or src:match("%.%.") or src:match("^%a[%w+.-]*:") then
    error("Refusing the resource '" .. src .. "': use a file of the doc directory")
  end
end

local function refuse_raw(raw)
  error("Refusing raw " .. raw.format .. " content in the documentation sources")
end

return {
  {
    Image = function(img)
      check_source(img.src)
    end,
    RawBlock = refuse_raw,
    RawInline = refuse_raw,
  },
}
