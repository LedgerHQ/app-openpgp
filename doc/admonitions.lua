-- Pandoc Lua filter: render RST admonitions as visible colored framed
-- boxes in LaTeX/PDF output, and as styled <div> blocks in HTML output.
--
-- Without this filter, Pandoc emits the admonition title as a plain
-- paragraph followed by the body, which is visually indistinguishable
-- from regular text in the generated PDF.

local types = {
  danger    = { title = "DANGER",    fg = "white", bg = "red!85!black"  },
  error     = { title = "ERROR",     fg = "white", bg = "red!85!black"  },
  warning   = { title = "WARNING",   fg = "black", bg = "orange!30"     },
  caution   = { title = "CAUTION",   fg = "black", bg = "orange!30"     },
  important = { title = "IMPORTANT", fg = "black", bg = "yellow!40"     },
  attention = { title = "ATTENTION", fg = "black", bg = "yellow!40"     },
  note      = { title = "NOTE",      fg = "black", bg = "blue!12"       },
  tip       = { title = "TIP",       fg = "black", bg = "green!18"      },
  hint      = { title = "HINT",      fg = "black", bg = "green!18"      },
}

local function has_title_subdiv(blk)
  return blk.t == "Div" and blk.classes and blk.classes:includes("title")
end

function Div(el)
  for _, cls in ipairs(el.classes) do
    local spec = types[cls]
    if spec then
      -- Drop the title sub-div that Pandoc auto-inserts for RST admonitions.
      local body = {}
      for _, blk in ipairs(el.content) do
        if not has_title_subdiv(blk) then
          table.insert(body, blk)
        end
      end

      if FORMAT:match("latex") then
        local open = pandoc.RawBlock(
          "latex",
          "\\begin{center}\\noindent\\fcolorbox{black}{" .. spec.bg ..
          "}{\\begin{minipage}{0.95\\textwidth}\\vspace{2pt}" ..
          "\\textcolor{" .. spec.fg .. "}{\\textbf{" .. spec.title ..
          "}}\\par\\vspace{4pt}"
        )
        local close = pandoc.RawBlock(
          "latex",
          "\\end{minipage}}\\end{center}"
        )
        table.insert(body, 1, open)
        table.insert(body, close)
        return body
      end

      if FORMAT:match("html") then
        local title = pandoc.RawBlock(
          "html",
          '<p class="admonition-title">' .. spec.title .. "</p>"
        )
        table.insert(body, 1, title)
        el.content = body
        el.classes = { "admonition", cls }
        return el
      end
    end
  end
end
