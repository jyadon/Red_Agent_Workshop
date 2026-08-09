type MessageLike = {
  content?: unknown
  text?: unknown
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function contentToText(content: unknown): string | null {
  if (typeof content === 'string') {
    return content
  }

  if (Array.isArray(content)) {
    const parts = content
      .map((item) => {
        if (typeof item === 'string') return item
        if (!isRecord(item)) return null

        if (typeof item.text === 'string') return item.text
        if (typeof item.content === 'string') return item.content
        if (typeof item.value === 'string') return item.value

        return null
      })
      .filter((item): item is string => Boolean(item))

    return parts.length > 0 ? parts.join('\n') : null
  }

  if (isRecord(content)) {
    if (typeof content.text === 'string') return content.text
    if (typeof content.content === 'string') return content.content
    if (typeof content.value === 'string') return content.value
  }

  return null
}

function messageToText(message: unknown): string | null {
  if (typeof message === 'string') {
    return message
  }

  if (!isRecord(message)) {
    return null
  }

  const msg = message as MessageLike
  return contentToText(msg.content) ?? contentToText(msg.text)
}

export function extractFinalOutputText(output: unknown): string | null {
  if (output == null) {
    return null
  }

  if (typeof output === 'string') {
    return output
  }

  if (!isRecord(output)) {
    return null
  }

  if (Array.isArray(output.messages) && output.messages.length > 0) {
    const lastMessage = output.messages[output.messages.length - 1]
    const text = messageToText(lastMessage)
    if (text) return text
  }

  return contentToText(output.content) ?? contentToText(output.message)
}

function extractFinalChannelText(text: string): string {
  const finalChannelPattern =
    /<\|channel\|>\s*final\s*(?:<\|message\|>|<\|content\|>)?/gi
  let match: RegExpExecArray | null = null
  let lastFinal: RegExpExecArray | null = null

  while ((match = finalChannelPattern.exec(text)) !== null) {
    lastFinal = match
  }

  if (!lastFinal) {
    return text
  }

  const start = lastFinal.index + lastFinal[0].length
  const nextChannel = text.slice(start).search(/<\|channel\|>/i)
  return nextChannel === -1 ? text.slice(start) : text.slice(start, start + nextChannel)
}

export function sanitizeAssistantText(text: string): string {
  return extractFinalChannelText(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/<\|channel\|>\s*thought\s*(?:<\|message\|>|<\|content\|>)?[\s\S]*?(?=<\|channel\|>|$)/gi, '')
    .replace(/<\|channel\|>\s*(?:analysis|thought)\b[\s\S]*?(?=<\|channel\|>|$)/gi, '')
    .replace(/<\|channel\|>\s*\w+\s*(?:<\|message\|>|<\|content\|>)?/gi, '')
    .replace(/<\|(?:message|content|end)\|>/gi, '')
    .replace(/<\|?channel>thought/gi, '')
    .replace(/<channel\|?>\s*thought/gi, '')
    .replace(/<\|?channel\|?>/gi, '')
    .replace(/<channel\|?>/gi, '')
    .replace(/^```markdown\s*/i, '')
    .replace(/^```md\s*/i, '')
    .replace(/```$/i, '')
    .trim()
}
