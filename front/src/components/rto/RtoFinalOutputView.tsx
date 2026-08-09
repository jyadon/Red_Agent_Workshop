// RTO-specific result view. Intentionally kept separate (duplicated) from the
// remediation/retest FinalOutputView so RTO and retest can evolve their result
// rendering independently without affecting each other.
import { useState, type ReactNode } from 'react'
import { extractFinalOutputText, sanitizeAssistantText } from '../../lib/final-output'

interface RtoFinalOutputViewProps {
  data: unknown
}

export function RtoFinalOutputView({ data }: RtoFinalOutputViewProps) {
  if (data == null) {
    return <EmptyBlock label="No output" />
  }

  if (typeof data === 'string') {
    return <SmartStringBlock text={sanitizeAssistantText(data)} />
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return <PlainValue value={String(data)} />
  }

  if (Array.isArray(data)) {
    return <ArrayBlock items={data} />
  }

  if (typeof data === 'object') {
    const obj = data as Record<string, unknown>

    if (isToolResult(obj)) {
      return <ToolResultCard result={obj} />
    }

    const finalText = extractFinalOutputText(obj)
    if (finalText) {
      return <SmartStringBlock text={finalText} />
    }

    return <ObjectBlock obj={obj} />
  }

  return <RawBlock data={data} />
}

/* =========================
   Normalization
========================= */

function isToolResult(obj: Record<string, unknown>) {
  return (
    ('command' in obj || 'tool_name' in obj) &&
    ('stdout' in obj ||
      'output' in obj ||
      'stderr' in obj ||
      'exit_code' in obj ||
      'exitCode' in obj)
  )
}

/* =========================
   Layout
========================= */

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-sm font-medium text-text-muted">{title}</div>
      {children}
    </div>
  )
}

function Card({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-border bg-bg-primary p-4">{children}</div>
}

/* =========================
   Smart string / markdown-like
========================= */

function SmartStringBlock({ text }: { text: string }) {
  const normalized = sanitizeAssistantText(text)

  if (looksLikeMarkdown(normalized)) {
    return <MarkdownLikeBlock text={normalized} />
  }

  return (
    <div className="whitespace-pre-wrap text-sm leading-relaxed text-text-secondary">
      {renderInline(normalized)}
    </div>
  )
}

function looksLikeMarkdown(text: string) {
  return /(^|\n)#{1,}\s+|(^|\n)\s*(-|\*)\s+|(^|\n)\s*\d+\.\s|```|\|.+\||^\s*---+\s*$/m.test(text)
}

function MarkdownLikeBlock({ text }: { text: string }) {
  const lines = text.split('\n')
  const blocks: ReactNode[] = []

  let i = 0
  while (i < lines.length) {
    const line = lines[i]

    if (/^\s*---+\s*$/.test(line.trim())) {
      blocks.push(<hr key={`hr-${blocks.length}`} className="my-4 border-border" />)
      i++
      continue
    }

    // Highlight only when the entire line is ==...== (ignore inline == to avoid
    // clashing with things like user==password in observation text).
    const highlight = line.trim().match(/^==(.+)==$/)
    if (highlight) {
      blocks.push(
        <div key={`hl-${blocks.length}`} className="my-1">
          <span className="rounded bg-yellow-300 px-2 py-1 text-base font-bold text-black">
            {renderInline(highlight[1])}
          </span>
        </div>,
      )
      i++
      continue
    }

    if (line.startsWith('```')) {
      const lang = line.slice(3).trim()
      i++
      const codeLines: string[] = []
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      i++
      blocks.push(
        <CodeBlockWithCopy
          key={`code-${blocks.length}`}
          code={codeLines.join('\n')}
          language={lang}
        />,
      )
      continue
    }

    if (isTableHeaderLine(line) && isTableDividerLine(lines[i + 1] ?? '')) {
      const header = splitTableRow(line)
      i += 2

      const rows: string[][] = []
      while (i < lines.length && isTableDataLine(lines[i])) {
        rows.push(splitTableRow(lines[i]))
        i++
      }

      blocks.push(
        <MarkdownTable key={`table-${blocks.length}`} header={header} rows={rows} />,
      )
      continue
    }

    const heading = line.match(/^(#{1,})\s+(.+)$/)
    if (heading) {
      blocks.push(
        <MarkdownHeading
          key={`h-${blocks.length}`}
          level={heading[1].length}
          content={heading[2]}
        />,
      )
      i++
      continue
    }

    if (/^\s*(-|\*)\s+/.test(line)) {
      const items: string[] = []
      const indents: number[] = []

      while (i < lines.length && /^\s*(-|\*)\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*(-|\*)\s+/, ''))
        indents.push(getIndentLevel(lines[i]))
        i++
      }

      blocks.push(
        <MarkdownList
          key={`ul-${blocks.length}`}
          items={items}
          indents={indents}
          ordered={false}
        />,
      )
      continue
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = []
      const indents: number[] = []

      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''))
        indents.push(getIndentLevel(lines[i]))
        i++
      }

      blocks.push(
        <MarkdownList
          key={`ol-${blocks.length}`}
          items={items}
          indents={indents}
          ordered
        />,
      )
      continue
    }

    if (line.trim() === '') {
      i++
      continue
    }

    const paragraphLines: string[] = [line]
    i++
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !/^\s*---+\s*$/.test(lines[i]) &&
      !/^#{1,}\s+/.test(lines[i]) &&
      !/^\s*(-|\*)\s+/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !/^```/.test(lines[i]) &&
      !(isTableHeaderLine(lines[i]) && isTableDividerLine(lines[i + 1] ?? ''))
    ) {
      paragraphLines.push(lines[i])
      i++
    }

    blocks.push(
      <p
        key={`p-${blocks.length}`}
        className="whitespace-pre-wrap text-sm leading-relaxed text-text-secondary"
      >
        {renderInline(paragraphLines.join('\n'))}
      </p>,
    )
  }

  return <div className="space-y-3">{blocks}</div>
}

function MarkdownHeading({ level, content }: { level: number; content: string }) {
  const clampedLevel = Math.min(Math.max(level, 1), 6)
  const classNameByLevel: Record<number, string> = {
    1: 'text-xl font-semibold text-text-primary',
    2: 'text-lg font-semibold text-text-primary',
    3: 'text-base font-semibold text-text-primary',
    4: 'text-sm font-semibold text-text-primary',
    5: 'text-sm font-medium text-text-primary',
    6: 'text-xs font-medium uppercase text-text-muted',
  }

  if (clampedLevel === 1) {
    return <h3 className={classNameByLevel[1]}>{renderInline(content)}</h3>
  }
  if (clampedLevel === 2) {
    return <h4 className={classNameByLevel[2]}>{renderInline(content)}</h4>
  }
  if (clampedLevel === 3) {
    return <h5 className={classNameByLevel[3]}>{renderInline(content)}</h5>
  }

  return <h6 className={classNameByLevel[clampedLevel]}>{renderInline(content)}</h6>
}

/* =========================
   Inline renderers
========================= */

function renderInline(text: string): ReactNode[] {
  const tokens = tokenizeInline(text)

  return tokens.map((token, idx) => {
    if (token.type === 'strong') {
      return (
        <strong key={idx} className="font-semibold text-text-primary">
          {token.content}
        </strong>
      )
    }

    if (token.type === 'code') {
      return (
        <code
          key={idx}
          className="rounded border border-terminal-border bg-terminal-bg px-1.5 py-0.5 font-mono text-[0.9em] text-terminal-text"
        >
          {token.content}
        </code>
      )
    }

    if (token.type === 'link') {
      return (
        <a
          key={idx}
          href={token.href}
          target="_blank"
          rel="noreferrer"
          className="text-accent underline underline-offset-2 hover:opacity-90"
        >
          {token.content}
        </a>
      )
    }

    return <span key={idx}>{token.content}</span>
  })
}

type InlineToken =
  | { type: 'text'; content: string }
  | { type: 'strong'; content: string }
  | { type: 'code'; content: string }
  | { type: 'link'; content: string; href: string }

function tokenizeInline(text: string): InlineToken[] {
  const tokens: InlineToken[] = []
  let i = 0

  while (i < text.length) {
    if (text.startsWith('**', i)) {
      const end = text.indexOf('**', i + 2)
      if (end !== -1) {
        tokens.push({
          type: 'strong',
          content: text.slice(i + 2, end),
        })
        i = end + 2
        continue
      }
    }

    if (text[i] === '`') {
      const end = text.indexOf('`', i + 1)
      if (end !== -1) {
        tokens.push({
          type: 'code',
          content: text.slice(i + 1, end),
        })
        i = end + 1
        continue
      }
    }

    if (text[i] === '[') {
      const textEnd = text.indexOf(']', i + 1)
      const openParen = textEnd !== -1 ? text.indexOf('(', textEnd + 1) : -1
      const closeParen = openParen !== -1 ? text.indexOf(')', openParen + 1) : -1

      if (textEnd !== -1 && openParen === textEnd + 1 && closeParen !== -1) {
        tokens.push({
          type: 'link',
          content: text.slice(i + 1, textEnd),
          href: text.slice(openParen + 1, closeParen),
        })
        i = closeParen + 1
        continue
      }
    }

    let j = i + 1
    while (
      j < text.length &&
      !text.startsWith('**', j) &&
      text[j] !== '`' &&
      text[j] !== '['
    ) {
      j++
    }

    tokens.push({
      type: 'text',
      content: text.slice(i, j),
    })
    i = j
  }

  return tokens
}

/* =========================
   Table helpers
========================= */

function isTableHeaderLine(line: string) {
  return line.includes('|')
}

function isTableDividerLine(line: string) {
  const parts = line.split('|').map((s) => s.trim()).filter(Boolean)
  return parts.length > 0 && parts.every((part) => /^:?-{3,}:?$/.test(part))
}

function isTableDataLine(line: string) {
  return line.includes('|') && line.trim() !== ''
}

function splitTableRow(line: string) {
  return line
    .split('|')
    .map((s) => s.trim())
    .filter((_, idx, arr) => !(idx === 0 && arr[idx] === '') && !(idx === arr.length - 1 && arr[idx] === ''))
}

function MarkdownTable({ header, rows }: { header: string[]; rows: string[][] }) {
  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="bg-bg-tertiary">
            {header.map((h, idx) => (
              <th key={idx} className="border border-border px-3 py-2 text-left font-medium text-text-primary">
                {renderInline(h)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rIdx) => (
            <tr key={rIdx} className="align-top">
              {header.map((_, cIdx) => (
                <td key={cIdx} className="border border-border px-3 py-2 text-text-secondary">
                  {renderInline(row[cIdx] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* =========================
   List helpers
========================= */

function getIndentLevel(line: string) {
  const match = line.match(/^(\s*)/)
  return match ? match[1].length : 0
}

function MarkdownList({
  items,
  indents,
  ordered,
}: {
  items: string[]
  indents: number[]
  ordered: boolean
}) {
  return (
    <div className="space-y-1">
      {items.map((item, idx) => {
        const indent = Math.floor((indents[idx] ?? 0) / 2)
        return (
          <div
            key={idx}
            className="flex text-sm text-text-secondary"
            style={{ marginLeft: `${indent * 16}px` }}
          >
            <span className="mr-2 min-w-[1.25rem] text-text-muted">
              {ordered ? `${idx + 1}.` : '•'}
            </span>
            <div className="min-w-0">{renderInline(item)}</div>
          </div>
        )
      })}
    </div>
  )
}

/* =========================
   Copyable code block
========================= */

function CodeBlockWithCopy({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      // noop
    }
  }

  return (
    <div className="rounded border border-terminal-border bg-terminal-bg">
      <div className="flex items-center justify-between border-b border-terminal-border px-3 py-2">
        <div className="text-xs text-text-muted">{language || 'code'}</div>
        <button
          type="button"
          onClick={handleCopy}
          className="rounded border border-border px-2 py-1 text-xs text-text-secondary hover:bg-bg-tertiary"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-xs text-terminal-text">
        <code>{code}</code>
      </pre>
    </div>
  )
}

/* =========================
   Tool result UI
========================= */

function ToolResultCard({ result }: { result: Record<string, unknown> }) {
  const command =
    typeof result.command === 'string'
      ? result.command
      : typeof result.tool_name === 'string'
        ? result.tool_name
        : null

  const stdout =
    typeof result.stdout === 'string'
      ? result.stdout
      : typeof result.output === 'string'
        ? result.output
        : null

  const stderr = typeof result.stderr === 'string' ? result.stderr : null

  const exitCode =
    typeof result.exit_code === 'number'
      ? result.exit_code
      : typeof result.exitCode === 'number'
        ? result.exitCode
        : null

  const observation =
    typeof result.brief_observation === 'string'
      ? result.brief_observation
      : typeof result.observation === 'string'
        ? result.observation
        : null

  const success = exitCode == null ? null : exitCode === 0

  return (
    <Card>
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-medium text-text-primary">Execution Result</div>
        {exitCode != null && (
          <span
            className={`rounded px-2 py-0.5 text-xs font-medium ${
              success ? 'bg-green-950/30 text-green-400' : 'bg-red-950/30 text-red-400'
            }`}
          >
            Exit: {exitCode}
          </span>
        )}
      </div>

      {command && (
        <Section title="Command">
          <CodeBlockWithCopy code={command} language="bash" />
        </Section>
      )}

      {observation && (
        <Section title="Observation">
          <div className="whitespace-pre-wrap text-sm text-text-secondary">
            {renderInline(observation)}
          </div>
        </Section>
      )}

      {stdout && (
        <Section title="Stdout">
          <CodeBlockWithCopy code={stdout} language="text" />
        </Section>
      )}

      {stderr && (
        <Section title="Stderr">
          <pre className="overflow-x-auto rounded border border-red-900/40 bg-red-950/20 p-3 font-mono text-xs text-red-300">
            <code>{stderr}</code>
          </pre>
        </Section>
      )}
    </Card>
  )
}

/* =========================
   Generic object / array
========================= */

function ArrayBlock({ items }: { items: unknown[] }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={i} className="rounded border border-border bg-bg-primary p-3">
          <RtoFinalOutputView data={item} />
        </div>
      ))}
    </div>
  )
}

function ObjectBlock({ obj }: { obj: Record<string, unknown> }) {
  const entries = Object.entries(obj)

  if ('message' in obj && typeof obj.message === 'string') {
    return <SmartStringBlock text={obj.message} />
  }

  if ('content' in obj && typeof obj.content === 'string') {
    const restEntries = entries.filter(([key]) => key !== 'content')

    return (
      <div className="space-y-4">
        <Section title="Content">
          <SmartStringBlock text={obj.content} />
        </Section>

        {restEntries.map(([key, value]) => (
          <Section key={key} title={key}>
            <ValueRenderer value={value} />
          </Section>
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {entries.map(([key, value]) => (
        <Section key={key} title={key}>
          <ValueRenderer value={value} />
        </Section>
      ))}
    </div>
  )
}

function ValueRenderer({ value }: { value: unknown }) {
  if (value == null) {
    return <span className="text-xs text-text-muted">null</span>
  }

  if (typeof value === 'string') {
    return <SmartStringBlock text={value} />
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return <PlainValue value={String(value)} />
  }

  if (Array.isArray(value)) {
    return <ArrayBlock items={value} />
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>

    if (isToolResult(obj)) {
      return <ToolResultCard result={obj} />
    }

    return <ObjectBlock obj={obj} />
  }

  return <RawBlock data={value} />
}

/* =========================
   Small display blocks
========================= */

function PlainValue({ value }: { value: string }) {
  return <span className="text-sm text-text-primary">{value}</span>
}

function RawBlock({ data }: { data: unknown }) {
  return (
    <pre className="overflow-x-auto rounded border border-border bg-bg-primary p-3 font-mono text-xs text-text-secondary">
      <code>{JSON.stringify(data, null, 2)}</code>
    </pre>
  )
}

function EmptyBlock({ label }: { label: string }) {
  return (
    <div className="rounded border border-border bg-bg-primary p-4 text-sm text-text-muted">
      {label}
    </div>
  )
}
