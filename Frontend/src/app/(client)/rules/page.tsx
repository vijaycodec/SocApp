'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useClient } from '@/contexts/ClientContext'
import { wazuhApi } from '@/lib/api'
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  AdjustmentsHorizontalIcon,
  FunnelIcon,
  XMarkIcon,
  DocumentTextIcon,
  ArrowDownTrayIcon,
  WrenchScrewdriverIcon,
  PlusIcon,
  ArrowUpTrayIcon,
  TrashIcon,
  EyeIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  PencilSquareIcon,
} from '@heroicons/react/24/outline'
import { clsx } from 'clsx'

// ─── Types ───────────────────────────────────────────────────────────────────

interface RuleDetails {
  match?: { pattern: string }
  regex?: { pattern: string }
  frequency?: string
  timeframe?: string
  if_matched_sid?: string
  [key: string]: unknown
}

interface WazuhRule {
  id: number
  level: number
  status: string
  filename: string
  relative_dirname: string
  description: string
  groups: string[]
  details: RuleDetails
  pci_dss: string[]
  gdpr: string[]
  gpg13: string[]
  hipaa: string[]
  nist_800_53: string[]
}

interface RuleFile {
  filename: string
  relative_dirname: string
  status: string
}

// ─── XML Pretty Printer ──────────────────────────────────────────────────────

function prettyPrintXml(xml: string): string {
  if (!xml || !xml.trim()) return xml

  const INDENT = '  '
  let level = 0
  const lines: string[] = []

  // Tokenise: handles comments, PI, CDATA, closing, self-closing, opening tags, text
  const tokenRegex =
    /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/[\w:.-]+\s*>|<[\w:.-][^>]*\/>|<[\w:.-][^>]*>|[^<>]+/g

  const tokens = (xml.match(tokenRegex) ?? []).filter(t => t.trim() !== '')

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]
    const t   = tok.trim()

    // Comment <!-- ... -->
    if (t.startsWith('<!--')) {
      t.split('\n').forEach((ln, idx) => {
        lines.push(idx === 0 ? INDENT.repeat(level) + ln.trim() : '  ' + ln.trim())
      })
      continue
    }

    // XML declaration / PI  <? ... ?>
    if (t.startsWith('<?')) {
      lines.push(INDENT.repeat(level) + t)
      continue
    }

    // CDATA
    if (t.startsWith('<![CDATA[')) {
      lines.push(INDENT.repeat(level) + t)
      continue
    }

    // Closing tag  </tag>
    if (t.startsWith('</')) {
      level = Math.max(0, level - 1)
      // If the last pushed line is an opening tag that has no children yet,
      // merge the closing tag onto the same line (handles <tag></tag>)
      const last = lines[lines.length - 1] ?? ''
      if (last.trimStart().startsWith('<') && !last.trimStart().startsWith('</') && !last.includes('\n')) {
        lines[lines.length - 1] = last + t
      } else {
        lines.push(INDENT.repeat(level) + t)
      }
      continue
    }

    // Self-closing  <tag />
    if (t.endsWith('/>')) {
      lines.push(INDENT.repeat(level) + t)
      continue
    }

    // Opening tag  <tag>
    if (t.startsWith('<')) {
      // Lookahead: if next token is plain text and the one after is the closing tag
      // → render as single inline line  <tag>text</tag>
      const nextTok  = tokens[i + 1]?.trim() ?? ''
      const nextNext = tokens[i + 2]?.trim() ?? ''
      if (
        nextTok && !nextTok.startsWith('<') &&
        nextNext && nextNext.startsWith('</')
      ) {
        lines.push(INDENT.repeat(level) + t + nextTok + nextNext)
        i += 2 // consumed the text + closing tag
        // level unchanged — we consumed the close tag too
        continue
      }
      lines.push(INDENT.repeat(level) + t)
      level++
      continue
    }

    // Plain text node — append to the last line
    if (lines.length > 0) {
      lines[lines.length - 1] += t
    } else {
      lines.push(t)
    }
  }

  return lines.join('\n')
}

// ─── XML Syntax Highlighter ──────────────────────────────────────────────────

function highlightXml(xml: string): string {
  const formatted = prettyPrintXml(xml)

  // HTML-escape a plain string (never call on strings that already contain spans)
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  // Highlight attr="value" pairs within a raw (un-escaped) attribute string.
  // Processes the raw text so the spans we insert here are never re-processed.
  const highlightAttrs = (attrStr: string) =>
    attrStr.replace(/([\w:.-]+)(="[^"]*")/g, (_, name: string, valPart: string) => {
      const val = valPart.slice(2, -1) // strip  ="  prefix and trailing  "
      return `<span class="text-orange-300">${name}</span>=<span class="text-green-300">"${esc(val)}"</span>`
    })

  // Tokenise the formatted XML into one token per XML construct.
  // Using the same token categories as prettyPrintXml so nothing is missed.
  const tokenRegex =
    /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/[\w:.-]+\s*>|<[\w:.-][^>]*\/?>|[^<]+/g

  return (formatted.match(tokenRegex) ?? [formatted])
    .map(tok => {
      // Comment  <!-- ... -->
      if (tok.startsWith('<!--')) {
        return `<span class="text-gray-500 italic">${esc(tok)}</span>`
      }
      // XML declaration / PI  <? ... ?>
      if (tok.startsWith('<?')) {
        const m = tok.match(/^<\?([\w:.-]+)([\s\S]*?)\?>$/)
        if (!m) return `<span class="text-yellow-400">${esc(tok)}</span>`
        return (
          `<span class="text-yellow-400">&lt;?${m[1]}</span>` +
          highlightAttrs(m[2]) +
          `<span class="text-yellow-400">?&gt;</span>`
        )
      }
      // CDATA section
      if (tok.startsWith('<![CDATA[')) {
        return `<span class="text-gray-400">${esc(tok)}</span>`
      }
      // Closing tag  </tagname>
      if (tok.startsWith('</')) {
        const m = tok.match(/^<\/([\w:.-]+)\s*>$/)
        if (!m) return esc(tok)
        return (
          `<span class="text-blue-400">&lt;/</span>` +
          `<span class="text-blue-300">${m[1]}</span>` +
          `<span class="text-blue-400">&gt;</span>`
        )
      }
      // Opening or self-closing tag  <tagname ...>  or  <tagname .../>
      if (tok.startsWith('<')) {
        const selfClose = tok.endsWith('/>')
        const m = tok.match(/^<([\w:.-]+)([\s\S]*?)(\/?>)$/)
        if (!m) return esc(tok)
        const [, name, attrs] = m
        return (
          `<span class="text-blue-400">&lt;</span>` +
          `<span class="text-blue-300 font-semibold">${name}</span>` +
          highlightAttrs(attrs) +
          `<span class="text-blue-400">${selfClose ? '/&gt;' : '&gt;'}</span>`
        )
      }
      // Text node or whitespace — escape and pass through as-is
      return esc(tok)
    })
    .join('')
}

// ─── XML Viewer Modal ────────────────────────────────────────────────────────

function XmlViewerModal({
  filename,
  orgId,
  onClose,
}: {
  filename: string
  orgId: string | undefined
  onClose: () => void
}) {
  const [content, setContent] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    setContent(null)

    wazuhApi.getRuleFileContent(filename, orgId)
      .then((res: { data?: { content?: string } }) => {
        if (!cancelled) setContent(res?.data?.content ?? '')
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load file')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => { cancelled = true }
  }, [filename, orgId])

  // close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  const handleDownload = () => {
    if (!content) return
    const blob = new Blob([content], { type: 'application/xml' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    /* backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      {/* dim layer */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* panel */}
      <div
        ref={panelRef}
        className="relative z-10 flex flex-col w-full max-w-4xl h-[85vh] rounded-2xl border border-gray-700 bg-gray-950 shadow-2xl overflow-hidden"
      >
        {/* header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-700 bg-gray-900 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <DocumentTextIcon className="w-5 h-5 text-blue-400 shrink-0" />
            <span className="font-mono text-sm text-blue-300 truncate">{filename}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-4">
            {content && (
              <button
                onClick={handleDownload}
                title="Download XML"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition-colors"
              >
                <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                Download
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
              title="Close"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* body */}
        <div className="flex-1 overflow-auto p-0">
          {loading && (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-gray-500">
              <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" />
              <span className="text-sm">Loading {filename}…</span>
            </div>
          )}

          {error && (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <p className="text-red-400 text-sm mb-1">Failed to load file</p>
                <p className="text-gray-500 text-xs">{error}</p>
              </div>
            </div>
          )}

          {!loading && !error && content !== null && (
            <div className="relative">
              {/* line numbers + code */}
              <div className="flex min-h-full">
                {/* line numbers */}
                <div className="select-none sticky left-0 bg-gray-900/80 text-right pr-4 pl-4 py-4 text-xs text-gray-600 font-mono leading-[1.625rem] shrink-0 border-r border-gray-800">
                  {content.split('\n').map((_, i) => (
                    <div key={i}>{i + 1}</div>
                  ))}
                </div>
                {/* highlighted code */}
                <pre
                  className="flex-1 px-5 py-4 text-xs font-mono leading-[1.625rem] text-gray-200 overflow-x-auto whitespace-pre"
                  dangerouslySetInnerHTML={{ __html: highlightXml(content) }}
                />
              </div>
            </div>
          )}
        </div>

        {/* footer */}
        {!loading && content && (
          <div className="px-5 py-2 border-t border-gray-800 bg-gray-900 shrink-0 flex items-center gap-4 text-xs text-gray-500">
            <span>{content.split('\n').length} lines</span>
            <span>{(new Blob([content]).size / 1024).toFixed(1)} KB</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── CSV → XML converter ─────────────────────────────────────────────────────

function parseCsvRows(text: string): Array<Record<string, string>> {
  const lines = text.trim().split(/\r?\n/)
  if (lines.length < 2) return []

  const headers = lines[0]
    .split(',')
    .map(h => h.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+|_+$/g, ''))

  return lines
    .slice(1)
    .filter(line => line.trim() && !line.trim().startsWith('#'))
    .map(line => {
      // Handle quoted fields (values may contain commas inside "…")
      const values: string[] = []
      let cur = ''
      let inQ = false
      for (let i = 0; i < line.length; i++) {
        const ch = line[i]
        if (ch === '"') { inQ = !inQ }
        else if (ch === ',' && !inQ) { values.push(cur.trim()); cur = '' }
        else { cur += ch }
      }
      values.push(cur.trim())

      const row: Record<string, string> = {}
      headers.forEach((h, i) => { row[h] = (values[i] ?? '').replace(/^"|"$/g, '') })
      return row
    })
}

function csvToXml(csvText: string): string {
  const xmlEsc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

  const rows = parseCsvRows(csvText)
  if (rows.length === 0) return DEFAULT_RULE_TEMPLATE

  // Collect all unique groups
  const groupSet = new Set<string>(['custom'])
  rows.forEach(r => { if (r.group || r.groups) groupSet.add((r.group || r.groups).replace(/,$/, '')) })
  const groupAttr = Array.from(groupSet).join(',') + ','

  const rulesXml = rows.map(row => {
    const id          = row.id || row.rule_id || '100001'
    const level       = row.level || '5'
    const desc        = row.description || row.desc || 'Custom rule'
    const match       = row.match || row.pattern || ''
    const regex       = row.regex || ''
    const ifSid       = row.if_sid || row.ifsid || row.parent_sid || ''
    const group       = (row.group || row.groups || '').replace(/,$/, '')
    const mitreId     = row.mitre_id || row.mitre || ''
    const mitreTactic = row.mitre_tactic || row.tactic || ''
    const frequency   = row.frequency || ''
    const timeframe   = row.timeframe || ''

    let xml = `  <rule id="${xmlEsc(id)}" level="${xmlEsc(level)}">\n`
    if (ifSid)                       xml += `    <if_sid>${xmlEsc(ifSid)}</if_sid>\n`
    if (match)                       xml += `    <match>${xmlEsc(match)}</match>\n`
    if (regex)                       xml += `    <regex>${xmlEsc(regex)}</regex>\n`
    if (frequency && timeframe)      xml += `    <frequency>${xmlEsc(frequency)}</frequency>\n    <timeframe>${xmlEsc(timeframe)}</timeframe>\n`
    xml += `    <description>${xmlEsc(desc)}</description>\n`
    if (group)                       xml += `    <group>${xmlEsc(group)},</group>\n`
    if (mitreId || mitreTactic) {
      xml += `    <mitre>\n`
      if (mitreId)     xml += `      <id>${xmlEsc(mitreId)}</id>\n`
      if (mitreTactic) xml += `      <tactic>${xmlEsc(mitreTactic)}</tactic>\n`
      xml += `    </mitre>\n`
    }
    xml += `  </rule>`
    return xml
  }).join('\n\n')

  return (
    `<group name="${xmlEsc(groupAttr)}">\n` +
    `  <!--\n` +
    `    Imported from CSV. Rule IDs >= 100000 are reserved for custom rules.\n` +
    `    Severity levels: 0=Ignored  3=Low  5=Medium  8=High  12=Critical  15=Severe\n` +
    `  -->\n\n` +
    rulesXml +
    `\n\n</group>`
  )
}

// ─── Default rule template ───────────────────────────────────────────────────

const DEFAULT_RULE_TEMPLATE = `<group name="custom,">
  <!--
    Custom detection rule.
    Rule IDs >= 100000 are reserved for custom rules.

    Severity levels:
      0  - Ignored      3  - Low      5  - Medium
      8  - High        12  - Critical  15  - Severe attack

    Docs: https://documentation.wazuh.com/current/user-manual/ruleset/custom-rules.html
  -->

  <rule id="100001" level="5">
    <if_sid>0</if_sid>
    <description>Custom rule — replace with your detection logic.</description>
    <group>custom,</group>
  </rule>

</group>`

// ─── New Rule File Editor (inline) ───────────────────────────────────────────

function NewRuleFileEditor({
  orgId,
  onBack,
  onSaved,
  initialFilename,
  initialContent,
}: {
  orgId: string | undefined
  onBack: () => void
  onSaved: () => void
  initialFilename?: string
  initialContent?: string
}) {
  const [filename, setFilename] = useState(initialFilename ?? 'custom_rules.xml')
  const [content, setContent]   = useState(initialContent ?? DEFAULT_RULE_TEMPLATE)
  const [saving, setSaving]     = useState(false)
  const [toast, setToast]       = useState<{ ok: boolean; msg: string } | null>(null)
  const importRef               = useRef<HTMLInputElement>(null)

  // Load a local XML or CSV file into the editor
  const handleLocalImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const isCsv = file.name.toLowerCase().endsWith('.csv')
    const reader = new FileReader()
    reader.onload = ev => {
      const raw = ev.target?.result as string ?? ''
      if (isCsv) {
        const xmlName = file.name.replace(/\.csv$/i, '.xml')
        setFilename(xmlName)
        setContent(csvToXml(raw))
      } else {
        setFilename(file.name)
        setContent(raw)
      }
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const handleSave = async () => {
    const name = filename.trim().endsWith('.xml') ? filename.trim() : `${filename.trim()}.xml`
    if (!name || name === '.xml') return
    setSaving(true)
    setToast(null)
    try {
      await wazuhApi.saveRuleFile(name, content, orgId)
      setToast({ ok: true, msg: `"${name}" saved successfully.` })
      setTimeout(() => onSaved(), 1000)
    } catch (err) {
      setToast({ ok: false, msg: err instanceof Error ? err.message : 'Save failed' })
    } finally {
      setSaving(false)
    }
  }

  const handleDownloadTemplate = () => {
    const csv = [
      '# Custom rules CSV import template',
      '# Columns: id, level, group, description, match, regex, if_sid, mitre_id, mitre_tactic',
      '# Rules ID must be >= 100000',
      '# Levels: 0=Ignored  3=Low  5=Medium  8=High  12=Critical  15=Severe',
      '# Leave a column blank if not needed',
      'id,level,group,description,match,regex,if_sid,mitre_id,mitre_tactic',
      '100200,5,authentication,SSH failed password attempt,Failed password for,,5716,T1110,Credential Access',
      '100201,10,authentication,SSH brute force detected - multiple failures,,,100200,T1110,Credential Access',
      '100202,8,privilege_escalation,Sudo privilege escalation by non-admin,sudo:,,5400,T1548,Privilege Escalation',
      '100203,5,file_integrity,Sensitive file modified in /etc,,,550,T1565,Impact',
      '100204,12,web_attack,SQL injection pattern detected in web log,,select.*from.*where,,T1190,Initial Access',
      '100205,10,web_attack,XSS attempt detected in HTTP request,,"<script>.*</script>",,T1059,Execution',
      '100206,8,network,Port scan detected from single source,,,533,T1046,Discovery',
      '100207,5,authentication,Failed login to management console,authentication failure,,31100,T1078,Defense Evasion',
      '100208,10,malware,Suspicious process execution from temp directory,,/tmp/[a-zA-Z0-9]+\\s,,T1059,Execution',
      '100209,12,data_exfiltration,Large outbound data transfer detected,,,,,',
      '100210,8,persistence,New cron job created by non-root user,crontab -,,,,',
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = 'custom_rules_template.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <nav className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 mb-1">
            <button onClick={onBack} className="hover:text-blue-500 transition-colors">Detection Rules</button>
            <span>/</span>
            <button onClick={onBack} className="hover:text-blue-500 transition-colors">Manage Rules</button>
            <span>/</span>
            <span className="text-gray-900 dark:text-white font-medium">New file</span>
          </nav>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <PlusIcon className="w-7 h-7 text-green-500" />
            Add new rules file
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Saved to /var/ossec/etc/rules/ on the manager
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadTemplate}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ArrowDownTrayIcon className="w-4 h-4" />
            CSV Template
          </button>
          <button
            onClick={() => importRef.current?.click()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ArrowUpTrayIcon className="w-4 h-4" />
            Import file
          </button>
          <input ref={importRef} type="file" accept=".xml,.csv" className="hidden" onChange={handleLocalImport} />
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ChevronLeftIcon className="w-4 h-4" />
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 text-white text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {saving ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <CheckCircleIcon className="w-4 h-4" />}
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {/* ── Toast ── */}
      {toast && (
        <div className={clsx(
          'px-4 py-3 rounded-lg text-sm flex items-center gap-2',
          toast.ok
            ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
        )}>
          {toast.ok
            ? <CheckCircleIcon className="w-5 h-5 shrink-0" />
            : <ExclamationCircleIcon className="w-5 h-5 shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── Filename ── */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
        <label className="text-sm text-gray-500 dark:text-gray-400 font-medium shrink-0">Filename</label>
        <input
          type="text"
          value={filename}
          onChange={e => setFilename(e.target.value)}
          placeholder="my_custom_rules.xml"
          className="flex-1 px-3 py-1.5 text-sm font-mono rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500"
        />
        <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0">
          {content.split('\n').length} lines
        </span>
      </div>

      {/* ── Editor ── */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden bg-white dark:bg-gray-900 shadow-sm">
        <div className="px-4 py-2 border-b border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60 flex items-center gap-2">
          <DocumentTextIcon className="w-4 h-4 text-gray-400" />
          <span className="text-xs text-gray-500 font-mono">{filename || 'custom_rules.xml'}</span>
        </div>
        <textarea
          value={content}
          onChange={e => setContent(e.target.value)}
          spellCheck={false}
          rows={30}
          className="w-full px-5 py-4 text-xs font-mono bg-transparent text-gray-800 dark:text-gray-200 leading-relaxed resize-y focus:outline-none"
        />
      </div>
    </div>
  )
}

// ─── Edit Rule File Editor (inline) ──────────────────────────────────────────

function EditRuleFileEditor({
  orgId,
  filename,
  onBack,
  onSaved,
}: {
  orgId: string | undefined
  filename: string
  onBack: () => void
  onSaved: () => void
}) {
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [toast, setToast]     = useState<{ ok: boolean; msg: string } | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    wazuhApi.getRuleFileContent(filename, orgId)
      .then((res: { data?: { content?: string } }) => {
        if (!cancelled) setContent(res?.data?.content ?? '')
      })
      .catch((err: unknown) => {
        if (!cancelled) setToast({ ok: false, msg: err instanceof Error ? err.message : 'Failed to load file' })
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [filename, orgId])

  const handleSave = async () => {
    setSaving(true)
    setToast(null)
    try {
      await wazuhApi.saveRuleFile(filename, content, orgId)
      setToast({ ok: true, msg: `"${filename}" saved successfully.` })
      setTimeout(() => onSaved(), 1000)
    } catch (err) {
      setToast({ ok: false, msg: err instanceof Error ? err.message : 'Save failed' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <nav className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 mb-1">
            <button onClick={() => { onBack(); onBack() }} className="hover:text-blue-500 transition-colors">Detection Rules</button>
            <span>/</span>
            <button onClick={onBack} className="hover:text-blue-500 transition-colors">Manage Rules</button>
            <span>/</span>
            <span className="text-gray-900 dark:text-white font-medium font-mono">{filename}</span>
          </nav>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <PencilSquareIcon className="w-7 h-7 text-blue-500" />
            Edit {filename}
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            /var/ossec/etc/rules/{filename}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ChevronLeftIcon className="w-4 h-4" />
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {saving ? <ArrowPathIcon className="w-4 h-4 animate-spin" /> : <CheckCircleIcon className="w-4 h-4" />}
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {/* ── Toast ── */}
      {toast && (
        <div className={clsx(
          'px-4 py-3 rounded-lg text-sm flex items-center gap-2',
          toast.ok
            ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
        )}>
          {toast.ok
            ? <CheckCircleIcon className="w-5 h-5 shrink-0" />
            : <ExclamationCircleIcon className="w-5 h-5 shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── Editor ── */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden bg-white dark:bg-gray-900 shadow-sm">
        <div className="px-4 py-2 border-b border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <DocumentTextIcon className="w-4 h-4 text-gray-400" />
            <span className="text-xs text-gray-500 font-mono">{filename}</span>
          </div>
          {!loading && (
            <span className="text-xs text-gray-400">{content.split('\n').length} lines</span>
          )}
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-24 gap-3 text-gray-400">
            <ArrowPathIcon className="w-7 h-7 animate-spin text-blue-500" />
            <span className="text-sm">Loading {filename}…</span>
          </div>
        ) : (
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            spellCheck={false}
            rows={30}
            className="w-full px-5 py-4 text-xs font-mono bg-transparent text-gray-800 dark:text-gray-200 leading-relaxed resize-y focus:outline-none"
          />
        )}
      </div>
    </div>
  )
}

// ─── Manage Rules View (inline) ───────────────────────────────────────────────

function ManageRulesView({
  orgId,
  onBack,
  onNewFile,
  onEditFile,
  onImportFile,
}: {
  orgId: string | undefined
  onBack: () => void
  onNewFile: () => void
  onEditFile: (filename: string) => void
  onImportFile: (filename: string, content: string) => void
}) {
  const [files, setFiles]       = useState<RuleFile[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState<string | null>(null)
  const [viewFile, setViewFile] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [toast, setToast]       = useState<{ ok: boolean; msg: string } | null>(null)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [isDragging, setIsDragging]    = useState(false)
  const [uploading, setUploading]      = useState(false)
  const importRef                      = useRef<HTMLInputElement>(null)
  const isValidFilename = (name: string) => /^[a-zA-Z0-9._-]+$/.test(name)

  const fetchFiles = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await wazuhApi.getRuleFiles({ orgId })
      const all: RuleFile[] = res?.data?.affected_items ?? []
      setFiles(all.filter(f => f.relative_dirname?.includes('etc/rules')))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rule files')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { fetchFiles() }, [fetchFiles])

  const handleDelete = async (filename: string) => {
    if (!confirm(`Delete "${filename}"? This cannot be undone.`)) return
    setDeleting(filename)
    setToast(null)
    try {
      await wazuhApi.deleteRuleFile(filename, orgId)
      setToast({ ok: true, msg: `"${filename}" deleted.` })
      await fetchFiles()
    } catch (err) {
      setToast({ ok: false, msg: err instanceof Error ? err.message : 'Delete failed' })
    } finally {
      setDeleting(null)
    }
  }

  // Stage files from the file picker for preview
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = Array.from(e.target.files ?? [])
    e.target.value = ''
    if (picked.length === 0) return
    setPendingFiles(prev => [...prev, ...picked.filter(f => !prev.some(p => p.name === f.name))])
  }

  // Stage files dropped onto the view
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const dropped = Array.from(e.dataTransfer.files).filter(f => f.name.toLowerCase().endsWith('.xml'))
    if (dropped.length === 0) return
    setPendingFiles(prev => [...prev, ...dropped.filter(f => !prev.some(p => p.name === f.name))])
  }

  // Upload all valid staged files to the manager
  const handleUpload = async () => {
    const validFiles = pendingFiles.filter(f => isValidFilename(f.name))
    if (validFiles.length === 0) return
    setUploading(true)
    const results = await Promise.allSettled(
      validFiles.map(file =>
        new Promise<string>((resolve, reject) => {
          const reader = new FileReader()
          reader.onload = async ev => {
            const raw = ev.target?.result as string ?? ''
            try {
              await wazuhApi.saveRuleFile(file.name, raw, orgId)
              resolve(file.name)
            } catch (err) {
              reject(new Error(`${file.name}: ${err instanceof Error ? err.message : 'Failed'}`))
            }
          }
          reader.onerror = () => reject(new Error(`${file.name}: Failed to read`))
          reader.readAsText(file)
        })
      )
    )
    setUploading(false)
    setPendingFiles([])
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[]
    if (failed.length === 0) {
      setToast({ ok: true, msg: `${succeeded} file${succeeded !== 1 ? 's' : ''} imported successfully.` })
    } else {
      const failMessages = failed.map(r => r.reason?.message ?? 'Unknown error').join('; ')
      setToast({ ok: false, msg: `${succeeded} succeeded, ${failed.length} failed: ${failMessages}` })
    }
    await fetchFiles()
  }

  const validPendingCount = pendingFiles.filter(f => isValidFilename(f.name)).length

  return (
    <div
      className="relative space-y-6"
      onDragOver={e => { e.preventDefault(); setIsDragging(true) }}
      onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setIsDragging(false) }}
      onDrop={handleDrop}
    >
      {/* ── Drag-over overlay ── */}
      {isDragging && (
        <div className="absolute inset-0 z-40 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-blue-500 bg-blue-500/10 pointer-events-none">
          <ArrowUpTrayIcon className="w-12 h-12 text-blue-400 mb-3" />
          <p className="text-lg font-semibold text-blue-400">Drop XML files here</p>
        </div>
      )}

      {/* ── File preview / staging modal ── */}
      {pendingFiles.length > 0 && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => { if (!uploading) setPendingFiles([]) }}
          />
          <div className="relative z-10 w-full max-w-lg rounded-2xl border border-gray-700 bg-gray-950 shadow-2xl overflow-hidden">

            {/* header */}
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-700 bg-gray-900">
              <div className="flex items-center gap-2">
                <ArrowUpTrayIcon className="w-5 h-5 text-blue-400" />
                <span className="font-semibold text-white">
                  {pendingFiles.length} file{pendingFiles.length !== 1 ? 's' : ''} staged
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => importRef.current?.click()}
                  disabled={uploading}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition-colors disabled:opacity-40"
                >
                  <PlusIcon className="w-3.5 h-3.5" />
                  Add more
                </button>
                <button
                  onClick={() => { if (!uploading) setPendingFiles([]) }}
                  className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                >
                  <XMarkIcon className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* file list */}
            <div className="divide-y divide-gray-800/60 max-h-72 overflow-y-auto">
              {pendingFiles.map((file, i) => {
                const valid = isValidFilename(file.name)
                return (
                  <div key={i} className="flex items-center gap-3 px-5 py-3">
                    <DocumentTextIcon className={clsx('w-5 h-5 shrink-0', valid ? 'text-blue-400' : 'text-red-400')} />
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-sm text-gray-200 truncate">{file.name}</p>
                      {!valid && (
                        <p className="text-xs text-red-400 mt-0.5">Invalid — spaces / special chars not allowed</p>
                      )}
                    </div>
                    <span className="text-xs text-gray-500 shrink-0">{(file.size / 1024).toFixed(1)} KB</span>
                    {valid
                      ? <CheckCircleIcon className="w-4 h-4 text-green-400 shrink-0" />
                      : <ExclamationCircleIcon className="w-4 h-4 text-red-400 shrink-0" />}
                    <button
                      onClick={() => setPendingFiles(pf => pf.filter((_, j) => j !== i))}
                      disabled={uploading}
                      className="p-1 rounded text-gray-500 hover:text-red-400 transition-colors disabled:opacity-40"
                    >
                      <XMarkIcon className="w-4 h-4" />
                    </button>
                  </div>
                )
              })}
            </div>

            {/* footer */}
            <div className="flex items-center justify-between px-5 py-4 border-t border-gray-800 bg-gray-900">
              <div className="text-xs">
                <span className="text-green-400 font-medium">{validPendingCount} valid</span>
                {pendingFiles.length - validPendingCount > 0 && (
                  <span className="text-red-400 font-medium ml-2">
                    {pendingFiles.length - validPendingCount} invalid
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPendingFiles([])}
                  disabled={uploading}
                  className="px-4 py-2 rounded-lg text-sm text-gray-300 hover:text-white border border-gray-700 hover:border-gray-600 transition-colors disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpload}
                  disabled={uploading || validPendingCount === 0}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-blue-600 hover:bg-blue-700 text-white font-medium disabled:opacity-50 transition-colors"
                >
                  {uploading
                    ? <><ArrowPathIcon className="w-4 h-4 animate-spin" />Uploading…</>
                    : `Upload ${validPendingCount} file${validPendingCount !== 1 ? 's' : ''}`}
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* XML viewer stays as modal (view-only popup is fine) */}
      {viewFile && (
        <XmlViewerModal filename={viewFile} orgId={orgId} onClose={() => setViewFile(null)} />
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <nav className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 mb-1">
            <button onClick={onBack} className="hover:text-blue-500 transition-colors">Detection Rules</button>
            <span>/</span>
            <span className="text-gray-900 dark:text-white font-medium">Manage Rules</span>
          </nav>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <WrenchScrewdriverIcon className="w-7 h-7 text-blue-500" />
            Manage Custom Rules
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Custom rule files in /var/ossec/etc/rules/
            {!loading && (
              <span className="ml-2 px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-xs">
                {files.length} file{files.length !== 1 ? 's' : ''}
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onNewFile}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 text-white text-sm font-medium transition-colors"
          >
            <PlusIcon className="w-4 h-4" />
            Add new rules file
          </button>
          <button
            onClick={() => importRef.current?.click()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium border border-gray-700 transition-colors"
          >
            <ArrowUpTrayIcon className="w-4 h-4" />
            Import files
          </button>
          <input ref={importRef} type="file" accept=".xml" multiple className="hidden" onChange={handleInputChange} />
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium border border-gray-200 dark:border-gray-700 transition-colors"
          >
            <ChevronLeftIcon className="w-4 h-4" />
            Back
          </button>
        </div>
      </div>

      {/* ── Toast ── */}
      {toast && (
        <div className={clsx(
          'px-4 py-3 rounded-lg text-sm flex items-center gap-2',
          toast.ok
            ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
        )}>
          {toast.ok
            ? <CheckCircleIcon className="w-5 h-5 shrink-0" />
            : <ExclamationCircleIcon className="w-5 h-5 shrink-0" />}
          {toast.msg}
        </div>
      )}

      {/* ── States ── */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-24 gap-3 text-gray-400">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" />
          <span className="text-sm">Loading custom rule files…</span>
        </div>
      )}

      {error && (
        <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 text-sm text-red-700 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && files.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 gap-3 text-gray-500">
          <DocumentTextIcon className="w-12 h-12 text-gray-300 dark:text-gray-700" />
          <p className="text-sm">No custom rule files found</p>
          <button
            onClick={onNewFile}
            className="mt-2 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 text-white text-sm font-medium transition-colors"
          >
            <PlusIcon className="w-4 h-4" /> Create your first rule file
          </button>
        </div>
      )}

      {/* ── Table ── */}
      {!loading && !error && files.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm bg-white dark:bg-gray-900">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/60">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">File</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Path</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-40">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {files.map(f => (
                <tr key={f.filename} className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-sm text-blue-600 dark:text-blue-400">{f.filename}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-500 dark:text-gray-400">/var/ossec/{f.relative_dirname}/</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setViewFile(f.filename)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-700 transition-colors"
                      >
                        <EyeIcon className="w-3.5 h-3.5" /> Show
                      </button>
                      <button
                        onClick={() => onEditFile(f.filename)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800 transition-colors"
                      >
                        <PencilSquareIcon className="w-3.5 h-3.5" /> Edit
                      </button>
                      <button
                        onClick={() => handleDelete(f.filename)}
                        disabled={deleting === f.filename}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 transition-colors disabled:opacity-50"
                      >
                        {deleting === f.filename
                          ? <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                          : <TrashIcon className="w-3.5 h-3.5" />}
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Compliance badges ────────────────────────────────────────────────────────

const ComplianceBadges = ({ rule }: { rule: WazuhRule }) => {
  const tags: { label: string; cls: string }[] = []
  if (rule.pci_dss?.length)     tags.push({ label: 'PCI-DSS', cls: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' })
  if (rule.gdpr?.length)        tags.push({ label: 'GDPR',    cls: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' })
  if (rule.hipaa?.length)       tags.push({ label: 'HIPAA',   cls: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400' })
  if (rule.nist_800_53?.length) tags.push({ label: 'NIST',    cls: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400' })
  if (rule.gpg13?.length)       tags.push({ label: 'GPG13',   cls: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400' })

  if (tags.length === 0) return <span className="text-gray-400 dark:text-gray-600 text-xs">—</span>

  return (
    <div className="flex flex-wrap gap-1">
      {tags.map(t => (
        <span key={t.label} className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', t.cls)}>
          {t.label}
        </span>
      ))}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

const PAGE_SIZE = 10

export default function RulesPage() {
  const { selectedClient, isClientMode } = useClient()

  const [allRules, setAllRules] = useState<WazuhRule[]>([])
  const [groups, setGroups]     = useState<string[]>([])
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState<string | null>(null)

  // filters
  const [search, setSearch]           = useState('')
  const [levelFilter, setLevelFilter] = useState('')
  const [groupFilter, setGroupFilter] = useState('')

  // pagination
  const [currentPage, setCurrentPage] = useState(1)

  // xml viewer
  const [xmlFile, setXmlFile] = useState<string | null>(null)

  // page view
  const [view, setView]         = useState<'list' | 'manage' | 'new-file' | 'edit-file'>('list')
  const [editFile, setEditFile] = useState<string | null>(null)
  const [importData, setImportData] = useState<{ filename: string; content: string } | null>(null)

  const orgId = isClientMode && selectedClient?.id ? selectedClient.id : undefined

  // ── fetch ──
  const fetchRules = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [rulesRes, groupsRes] = await Promise.all([
        wazuhApi.getRules({ orgId, limit: 10000 }),
        wazuhApi.getRuleGroups({ orgId }),
      ])
      setAllRules(rulesRes?.data?.affected_items ?? [])
      setGroups(groupsRes?.data?.affected_items ?? [])
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch rules')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { fetchRules() }, [fetchRules])
  useEffect(() => { setCurrentPage(1) }, [search, levelFilter, groupFilter])

  // ── filter ──
  const filtered = allRules.filter(r => {
    const q = search.toLowerCase()
    const matchSearch = !q ||
      String(r.id).includes(q) ||
      r.description?.toLowerCase().includes(q) ||
      r.filename?.toLowerCase().includes(q) ||
      r.groups?.some(g => g.toLowerCase().includes(q))

    const matchLevel = !levelFilter || (() => {
      const l = r.level
      if (levelFilter === 'critical') return l >= 12
      if (levelFilter === 'high')     return l >= 8 && l < 12
      if (levelFilter === 'medium')   return l >= 4 && l < 8
      if (levelFilter === 'low')      return l < 4
      return true
    })()

    const matchGroup = !groupFilter || r.groups?.includes(groupFilter)
    return matchSearch && matchLevel && matchGroup
  })

  // ── paginate ──
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safePage   = Math.min(currentPage, totalPages)
  const pageStart  = (safePage - 1) * PAGE_SIZE
  const pageRows   = filtered.slice(pageStart, pageStart + PAGE_SIZE)

  const pageNumbers = (() => {
    const pages: (number | 'ellipsis')[] = []
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)
      if (safePage > 3) pages.push('ellipsis')
      for (let i = Math.max(2, safePage - 1); i <= Math.min(totalPages - 1, safePage + 1); i++) pages.push(i)
      if (safePage < totalPages - 2) pages.push('ellipsis')
      pages.push(totalPages)
    }
    return pages
  })()

  const clearFilters = () => { setSearch(''); setLevelFilter(''); setGroupFilter('') }
  const hasFilters   = search || levelFilter || groupFilter

  // ── Manage / New-file views are rendered directly in the page ──
  if (view === 'manage') {
    return (
      <ManageRulesView
        orgId={orgId}
        onBack={() => setView('list')}
        onNewFile={() => { setImportData(null); setView('new-file') }}
        onEditFile={f => { setEditFile(f); setView('edit-file') }}
        onImportFile={(filename, content) => { setImportData({ filename, content }); setView('new-file') }}
      />
    )
  }

  if (view === 'new-file') {
    return (
      <NewRuleFileEditor
        orgId={orgId}
        onBack={() => { setImportData(null); setView('manage') }}
        onSaved={() => {
          setImportData(null)
          setView('manage')
          // Re-fetch rules so the list is up-to-date when the user navigates back
          fetchRules()
        }}
        initialFilename={importData?.filename}
        initialContent={importData?.content}
      />
    )
  }

  if (view === 'edit-file' && editFile) {
    return (
      <EditRuleFileEditor
        orgId={orgId}
        filename={editFile}
        onBack={() => setView('manage')}
        onSaved={() => {
          setView('manage')
          fetchRules()
        }}
      />
    )
  }

  return (
    <div className="space-y-6">

      {/* ── XML Viewer Modal ── */}
      {xmlFile && (
        <XmlViewerModal
          filename={xmlFile}
          orgId={orgId}
          onClose={() => setXmlFile(null)}
        />
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <AdjustmentsHorizontalIcon className="w-7 h-7 text-blue-500" />
            Detection Rules
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {allRules.length.toLocaleString()} rules loaded
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setView('manage')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium border border-gray-700 transition-colors"
          >
            <WrenchScrewdriverIcon className="w-4 h-4 text-blue-400" />
            Manage Rules
          </button>
          <button
            onClick={fetchRules}
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50 transition-colors"
          >
            <ArrowPathIcon className={clsx('w-4 h-4', loading && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[220px]">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by ID, description, group, file…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div className="relative">
          <FunnelIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          <select
            value={levelFilter}
            onChange={e => setLevelFilter(e.target.value)}
            className="pl-9 pr-8 py-2 text-sm border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 appearance-none"
          >
            <option value="">All Levels</option>
            <option value="critical">Critical (≥12)</option>
            <option value="high">High (8–11)</option>
            <option value="medium">Medium (4–7)</option>
            <option value="low">Low (0–3)</option>
          </select>
        </div>

        {groups.length > 0 && (
          <div className="relative">
            <FunnelIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
            <select
              value={groupFilter}
              onChange={e => setGroupFilter(e.target.value)}
              className="pl-9 pr-8 py-2 text-sm border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 appearance-none max-w-[200px]"
            >
              <option value="">All Groups</option>
              {groups.map(g => <option key={g} value={g}>{g}</option>)}
            </select>
          </div>
        )}

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="inline-flex items-center gap-1 px-3 py-2 text-sm text-gray-500 dark:text-gray-400 hover:text-red-500 dark:hover:text-red-400 border border-gray-200 dark:border-gray-700 rounded-lg transition-colors"
          >
            <XMarkIcon className="w-4 h-4" />
            Clear
          </button>
        )}

        <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">
          {filtered.length.toLocaleString()} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 text-sm text-red-700 dark:text-red-400">
          {error}
        </div>
      )}

      {/* ── Table ── */}
      <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm bg-white dark:bg-gray-900">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/60">
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-20">ID</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Description</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-44">Groups</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-52">Regulatory Compliance</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-52">File</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 w-36">Path</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
            {loading && (
              <tr>
                <td colSpan={6} className="px-4 py-16 text-center">
                  <div className="flex flex-col items-center gap-3 text-gray-400">
                    <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500" />
                    <span className="text-sm">Loading rules…</span>
                  </div>
                </td>
              </tr>
            )}
            {!loading && pageRows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-16 text-center text-sm text-gray-400 dark:text-gray-500">
                  No rules found
                  {hasFilters && <> — <button onClick={clearFilters} className="text-blue-500 hover:underline">clear filters</button></>}
                </td>
              </tr>
            )}
            {!loading && pageRows.map(rule => (
              <tr key={rule.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors">

                {/* ID */}
                <td className="px-4 py-3 align-top">
                  <div className="font-mono font-semibold text-gray-900 dark:text-gray-100">{rule.id}</div>
                </td>

                {/* Description */}
                <td className="px-4 py-3 align-top">
                  <p className="text-gray-800 dark:text-gray-200 leading-snug line-clamp-2">
                    {rule.description || <span className="text-gray-400">—</span>}
                  </p>
                </td>

                {/* Groups */}
                <td className="px-4 py-3 align-top">
                  <div className="flex flex-wrap gap-1">
                    {rule.groups?.length ? rule.groups.map(g => (
                      <span key={g} className="px-2 py-0.5 rounded-md text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                        {g}
                      </span>
                    )) : <span className="text-gray-400 text-xs">—</span>}
                  </div>
                </td>

                {/* Regulatory Compliance */}
                <td className="px-4 py-3 align-top">
                  <ComplianceBadges rule={rule} />
                </td>

                {/* File — clickable */}
                <td className="px-4 py-3 align-top">
                  {rule.filename ? (
                    <button
                      onClick={() => setXmlFile(rule.filename)}
                      className="group inline-flex items-center gap-1.5 font-mono text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 hover:underline underline-offset-2 text-left break-all transition-colors"
                      title={`Open ${rule.filename}`}
                    >
                      <DocumentTextIcon className="w-3.5 h-3.5 shrink-0 opacity-60 group-hover:opacity-100" />
                      {rule.filename}
                    </button>
                  ) : (
                    <span className="text-gray-400 text-xs">—</span>
                  )}
                </td>

                {/* Path */}
                <td className="px-4 py-3 align-top">
                  <span className="font-mono text-xs text-gray-500 dark:text-gray-400 break-all">
                    {rule.relative_dirname || <span className="text-gray-400">—</span>}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
      {!loading && filtered.length > 0 && (
        <div className="flex items-center justify-between flex-wrap gap-3">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Showing{' '}
            <span className="font-medium text-gray-700 dark:text-gray-300">{pageStart + 1}</span>–
            <span className="font-medium text-gray-700 dark:text-gray-300">{Math.min(pageStart + PAGE_SIZE, filtered.length)}</span>
            {' '}of{' '}
            <span className="font-medium text-gray-700 dark:text-gray-300">{filtered.length.toLocaleString()}</span> rules
          </p>

          <div className="flex items-center gap-1">
            <button onClick={() => setCurrentPage(1)} disabled={safePage === 1}
              className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors" title="First">
              <ChevronDoubleLeftIcon className="w-4 h-4" />
            </button>
            <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={safePage === 1}
              className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors" title="Previous">
              <ChevronLeftIcon className="w-4 h-4" />
            </button>

            {pageNumbers.map((p, i) =>
              p === 'ellipsis' ? (
                <span key={`e-${i}`} className="px-2 text-gray-400 dark:text-gray-600 text-sm select-none">…</span>
              ) : (
                <button key={p} onClick={() => setCurrentPage(p)}
                  className={clsx('min-w-[32px] h-8 px-2 rounded-lg border text-sm font-medium transition-colors',
                    p === safePage
                      ? 'bg-blue-600 border-blue-600 text-white shadow-sm'
                      : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
                  )}>
                  {p}
                </button>
              )
            )}

            <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={safePage === totalPages}
              className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors" title="Next">
              <ChevronRightIcon className="w-4 h-4" />
            </button>
            <button onClick={() => setCurrentPage(totalPages)} disabled={safePage === totalPages}
              className="p-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors" title="Last">
              <ChevronDoubleRightIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
