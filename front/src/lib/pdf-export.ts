import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

// Downloads a RTO report (Markdown) via the browser's "Print -> Save as PDF" flow.
// Rendering with the browser's own fonts avoids a PDF library (which would need
// embedded fonts) and backend generation.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

const PRINT_CSS = `
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, "Hiragino Sans", "Hiragino Kaku Gothic ProN",
      "Yu Gothic", "Meiryo", sans-serif;
    color: #111827; line-height: 1.7; font-size: 12px;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .report { max-width: 820px; margin: 0 auto; padding: 8px; }
  h1 { font-size: 1.9em; margin: 0 0 .6em; padding-bottom: .3em; border-bottom: 2px solid #e5e7eb; }
  h2 { font-size: 1.45em; margin: 1.4em 0 .5em; padding-bottom: .2em; border-bottom: 1px solid #e5e7eb; }
  h3 { font-size: 1.2em; margin: 1.1em 0 .4em; }
  h4, h5, h6 { margin: 1em 0 .4em; }
  p { margin: .5em 0; }
  ul, ol { margin: .5em 0; padding-left: 1.5em; }
  li { margin: .2em 0; }
  a { color: #1d4ed8; text-decoration: underline; }
  code { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
    background: #f3f4f6; padding: .1em .35em; border-radius: 4px; font-size: .9em; }
  pre { background: #f3f4f6; padding: 12px; border-radius: 6px; overflow-x: auto;
    white-space: pre-wrap; word-break: break-word; }
  pre code { background: none; padding: 0; }
  table { border-collapse: collapse; width: 100%; margin: .8em 0; font-size: .95em; }
  th, td { border: 1px solid #d1d5db; padding: 6px 10px; text-align: left; vertical-align: top; }
  th { background: #f9fafb; font-weight: 600; }
  hr { border: none; border-top: 1px solid #e5e7eb; margin: 1.2em 0; }
  blockquote { margin: .6em 0; padding: .2em .9em; border-left: 3px solid #d1d5db; color: #374151; }
  h1, h2, h3, h4 { break-after: avoid; }
  table, pre, blockquote { break-inside: avoid; }
`

/** Opens the Markdown in a separate print window and triggers the print (Save as PDF) dialog; `title` becomes the default PDF filename. */
export function downloadPdf(title: string, markdown: string): void {
  const bodyHtml = renderToStaticMarkup(
    createElement(ReactMarkdown, { remarkPlugins: [remarkGfm] }, markdown),
  )

  const doc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>${PRINT_CSS}</style>
</head>
<body><main class="report">${bodyHtml}</main></body>
</html>`

  // Do not set noopener: we need to keep control of the window to print it.
  const win = window.open('', '_blank', 'width=900,height=1000')
  if (!win) {
    window.alert(
      'Could not open the PDF export window. Please disable your browser\'s pop-up blocker.',
    )
    return
  }

  win.document.open()
  win.document.write(doc)
  win.document.close()
  win.focus()

  win.onafterprint = () => win.close()
  const triggerPrint = () => {
    try {
      win.print()
    } catch {
      // A failed print() is non-fatal in some environments.
    }
  }
  window.setTimeout(triggerPrint, 250)
}
