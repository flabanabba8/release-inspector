// Use the existing Hermes development dependencies; installs nothing.
// node tests/test_desktop.cjs /path/to/hermes-agent/node_modules
const fs = require('fs'), path = require('path'), os = require('os'), assert = require('assert/strict')
const modules = path.resolve(process.argv[2])
const { JSDOM } = require(path.join(modules, 'jsdom'))
const esbuild = require(path.join(modules, 'esbuild'))
const dom = new JSDOM('<!doctype html><div id="root"></div>', { url: 'http://localhost/' })
global.window = dom.window
global.document = dom.window.document
global.HTMLElement = dom.window.HTMLElement
global.IS_REACT_ACT_ENVIRONMENT = true
const timers = new Set(), nativeInterval = global.setInterval, nativeClear = global.clearInterval
global.setInterval = (...args) => { const id = nativeInterval(...args); timers.add(id); return id }
global.clearInterval = id => { timers.delete(id); nativeClear(id) }
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'release-inspector-ui-'))
;(async () => {
  try {
    const output = path.join(tmp, 'flow.cjs')
    esbuild.buildSync({ entryPoints: [path.join(__dirname, 'desktop_flow.js')], bundle: true,
      platform: 'node', format: 'cjs', outfile: output, nodePaths: [modules],
      alias: { '@hermes/plugin-sdk': path.join(__dirname, 'sdk_stub.js') } })
    const result = await require(output).run(assert, document)
    assert.equal(timers.size, 0, 'Plugin polling must stop on unmount')
    console.log(JSON.stringify(result))
  } finally { dom.window.close(); esbuild.stop(); fs.rmSync(tmp, { recursive: true, force: true }) }
// React's bundled browser scheduler can retain a Node MessagePort after jsdom
// closes. Plugin interval teardown is asserted above before the test process exits.
})().then(() => process.exit(0)).catch(error => { console.error(error); process.exit(1) })
