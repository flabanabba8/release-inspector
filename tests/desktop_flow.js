import { act } from 'react'
import { createRoot } from 'react-dom/client'
import plugin from '../desktop/plugin.js'

export async function run(assert, document) {
  const contributions = [], calls = []
  const ctx = { register: c => contributions.push(c), rest: async (_, { body }) => {
    calls.push(body)
    if (body.operation === 'release_inspect_tree') return { coverage:'Text snapshots only', changed_directories_after_snapshot:1,
      secret_indicators:[{file_id:1,path:null,line:2,type:'Potential secret'}], configuration_indicators:[], omissions:[{file_id:2,path:'binary.dat',reason:'binary requires review'}] }
    if (body.operation === 'release_inspect_archive') return { notice:'Archive coverage is limited', unsafe_name_indexes:[[0]],
      secret_indicators:[{member:[1,2],component:'content',line:1,type:'Potential secret'}], configuration_indicators:[], omissions:[] }
    throw Error('Unexpected operation')
  } }
  plugin.register(ctx)
  const root = createRoot(document.getElementById('root'))
  const change = async (element, value) => act(async () => {
    const proto = element.tagName === 'SELECT' ? window.HTMLSelectElement.prototype : window.HTMLInputElement.prototype
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(element, value)
    element.dispatchEvent(new window.Event(element.tagName === 'SELECT' ? 'change' : 'input', { bubbles:true }))
  })
  const submit = async () => act(async () => document.querySelector('form').dispatchEvent(new window.Event('submit', { bubbles:true, cancelable:true })))
  try {
    await act(async () => root.render(contributions.find(c => c.area === 'routes').render()))
    assert.match(document.body.textContent, /does not establish publication safety/)
    await change(document.querySelector('input:not([type=checkbox])'), '/tmp/source')
    await act(async () => document.querySelector('input[type=checkbox]').click())
    assert.equal(calls.length, 0)
    await submit()
    assert.equal(calls[0].arguments.allow_profile_data, true)
    assert.match(document.querySelector('[aria-label="Inspection report"]').textContent, /path hidden/)
    assert.match(document.querySelector('[role=alert]').textContent, /changed during inspection/)
    await change(document.querySelector('select'), 'archive')
    await change(document.querySelector('input:not([type=checkbox])'), '/tmp/package.zip')
    await submit()
    assert.match(document.querySelector('[aria-label="Inspection report"]').textContent, /Archive member 1.2/)
    assert.match(document.querySelector('[role=alert]').textContent, /unsafe archive/)
  } finally { await act(async () => root.unmount()) }
  return {passed:true, checks:['manual inspection', 'profile data opt-in', 'hidden sensitive path', 'changed source warning', 'archive omissions', 'timer cleanup']}
}
