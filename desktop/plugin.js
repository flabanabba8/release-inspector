import { ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { createElement as h, useState } from 'react'

const field = { padding: '8px 10px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: 7, background: 'var(--ui-bg-tertiary)', color: 'var(--ui-text-primary)' }
const card = { padding: 16, border: '1px solid var(--ui-stroke-secondary)', borderRadius: 12, display: 'grid', gap: 10 }
const button = (text, onClick, disabled = false, props = {}) => h('button', { style: { ...field, opacity: disabled ? 0.5 : 1 }, onClick, disabled, ...props }, text)
const label = (text, input) => h('label', null, text, input)

function location(item) {
  if (item.byte_offset != null) return `Byte offset ${item.byte_offset} (${item.encoding || 'unknown encoding'})`
  if (item.path) return item.path
  if (item.object_id) return `Git object ${item.object_id}`
  if (Array.isArray(item.member)) return `Archive member ${item.member.join('.')}`
  if (item.file_id != null) return `File ${item.file_id} (path hidden)`
  return item.object_type === 'ref_names' ? 'Git reference names' : 'Location withheld'
}
function Findings({ title, items, describe }) {
  return h('section', { style: card }, h('h2', null, `${title} · ${items.length}`),
    items.length === 0 && h('p', null, 'None reported by this limited check.'),
    h('ul', null, ...items.slice(0, 50).map((item, i) => h('li', { key: i }, `${location(item)}${item.line ? `, line ${item.line}` : ''}: ${describe(item)}`))),
    items.length > 50 && h('p', null, `${items.length - 50} additional item(s) not shown.`))
}
function Inspector({ ctx }) {
  const [mode, setMode] = useState('tree'), [path, setPath] = useState(''), [allowProfile, setAllowProfile] = useState(false)
  const [report, setReport] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState('')
  const call = (operation, args) => ctx.rest('/action', { method: 'POST', body: { operation, arguments: args }, timeoutMs: 65000 })
  const scan = () => {
    setBusy(true); setError(''); setReport(null)
    const operation = mode === 'git' ? 'release_inspect_git' : mode === 'archive' ? 'release_inspect_archive' : mode === 'binary' ? 'release_inspect_binary' : 'release_inspect_tree'
    const key = mode === 'git' ? 'repo_path' : mode === 'archive' ? 'archive_path' : mode === 'binary' ? 'artifact_path' : 'source_dir'
    call(operation, { [key]: path.trim(), allow_profile_data: allowProfile }).then(setReport).catch(e => setError(String(e.message || e))).finally(() => setBusy(false))
  }
  return h('main', { style: { maxWidth: 1000, padding: 28, margin: 'auto', display: 'grid', gap: 20, color: 'var(--ui-text-primary)' } },
    h('header', null, h('h1', null, 'Release Inspector'), h('p', null, 'Review potential secrets and personal configuration before sharing.')),
    h('p', { style: card }, 'A clean result does not establish publication safety. Review omissions, history, artifacts, screenshots, remote refs and personal configuration separately.'),
    error && h('p', { role: 'alert', style: card }, error),
    h('form', { style: card, onSubmit: e => { e.preventDefault(); scan() } },
      label('Inspection type', h('select', { style: { ...field, display: 'block' }, value: mode, disabled: busy, onChange: e => { setMode(e.target.value); setReport(null) } },
        h('option', { value:'tree' }, 'Current source tree'), h('option', { value:'git' }, 'Local Git history and refs'), h('option', { value:'archive' }, 'ZIP or APK'), h('option', { value:'binary' }, 'Binary literal strings'))),
      label('Path on the Hermes host', h('input', { style: { ...field, display: 'block', width: '100%' }, value: path, disabled: busy, onChange: e => { setPath(e.target.value); setReport(null) } })),
      label('Allow selected artifacts inside this profile’s plugin data', h('input', { type:'checkbox', checked:allowProfile, disabled:busy, onChange:e => { setAllowProfile(e.target.checked); setReport(null) } })),
      button(busy ? 'Inspecting…' : 'Inspect selected scope', undefined, busy || !path.trim(), { type:'submit' }),
      h('p', null, 'The check is bounded and may ask you to narrow a large scope. Detected sensitive filenames are hidden.')),
    report && h('div', { style: { display:'grid', gap:14 }, 'aria-label':'Inspection report' },
      h('div', { style:card, role:'status' }, h('strong', null, 'Inspection complete'), h('p', null, report.coverage || report.notice),
        (report.refs_changed_during_scan || report.changed_directories_after_snapshot > 0) && h('p', { role:'alert' }, 'The source changed during inspection. Review changes and inspect again.'),
        report.strings_skipped > 0 && h('p', { role:'alert' }, `${report.strings_skipped} binary string(s) were skipped and require separate review.`),
        report.unsafe_name_indexes?.length > 0 && h('p', { role:'alert' }, `${report.unsafe_name_indexes.length} unsafe archive member name(s) require review.`)),
      h(Findings, { title:'Secret indicators', items:report.secret_indicators || [], describe:item => item.type || 'Potential secret' }),
      h(Findings, { title:'Configuration indicators', items:report.configuration_indicators || [], describe:item => (item.categories || []).join(', ') }),
      h(Findings, { title:'Omissions', items:report.omissions || report.scanner_omissions || [], describe:item => item.reason || 'Separate review required' })))
}

export default { id:'release-inspector', name:'Release Inspector', register(ctx) {
  ctx.register({ id:'page', area:ROUTES_AREA, data:{path:'/release-inspector'}, render:() => h(Inspector, {ctx}) })
  ctx.register({ id:'nav', area:SIDEBAR_NAV_AREA, data:{path:'/release-inspector', label:'Release Inspector', codicon:'shield'} })
} }
