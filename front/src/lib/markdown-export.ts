import { extractFinalOutputText, sanitizeAssistantText } from './final-output'

/** Extract the Markdown body from a thread's final_output, falling back to JSON if no text can be found. */
export function extractMarkdownReport(output: unknown): string {
  const text = extractFinalOutputText(output)
  if (text != null && text.trim() !== '') {
    return sanitizeAssistantText(text)
  }
  return '```json\n' + JSON.stringify(output, null, 2) + '\n```'
}

/** Download a string as a .md file from the browser. */
export function downloadMarkdown(filename: string, content: string): void {
  const safeName = filename.toLowerCase().endsWith('.md') ? filename : `${filename}.md`
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = safeName
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
