import assert from 'node:assert/strict'
import { execFile as execFileCallback } from 'node:child_process'
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

import {
  generateCargoBundle,
  generatePnpmBundle,
} from './generate-third-party-licenses.mjs'

const execFile = promisify(execFileCallback)
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
const fixtureRoot = path.join(scriptDirectory, 'fixtures', 'third-party-licenses')
const generatorPath = path.join(scriptDirectory, 'generate-third-party-licenses.mjs')

async function fixtureJson(name) {
  const contents = await readFile(path.join(fixtureRoot, name), 'utf8')
  return JSON.parse(contents.replaceAll('__FIXTURE_ROOT__', fixtureRoot))
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'routerview-license-test-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  return directory
}

test('rejects a malformed dependency report fixture', async (t) => {
  const output = await temporaryDirectory(t)
  await assert.rejects(
    execFile(process.execPath, [
      generatorPath,
      'pnpm',
      path.join(fixtureRoot, 'malformed.json'),
      output,
    ]),
    (error) => {
      assert.match(error.stderr, /not valid JSON/)
      return true
    },
  )
})

test('fails when a release dependency has no license text', async (t) => {
  const output = await temporaryDirectory(t)
  const report = await fixtureJson('pnpm-missing-license.json')
  await assert.rejects(
    generatePnpmBundle(report, output, []),
    /pnpm package missing-license@1\.0\.0 has no recognized regular license or notice file/,
  )
})

test('deduplicates repeated pnpm dependencies after validating each copy', async (t) => {
  const output = await temporaryDirectory(t)
  const report = await fixtureJson('pnpm-duplicate.json')
  assert.equal(await generatePnpmBundle(report, output, []), 1)

  const entries = await readdir(path.join(output, 'pnpm'), { withFileTypes: true })
  const packageDirectories = entries.filter((entry) => entry.isDirectory())
  assert.deepEqual(packageDirectories.map((entry) => entry.name), ['fixture-package-1.2.3'])
  assert.equal(
    await readFile(path.join(output, 'pnpm', 'fixture-package-1.2.3', 'LICENSE'), 'utf8'),
    'Fixture license text.\n',
  )
  assert.equal(
    await readFile(path.join(output, 'pnpm', 'fixture-package-1.2.3', 'UNLICENSE'), 'utf8'),
    'Fixture unlicense text.\n',
  )
  assert.equal(
    await readFile(path.join(output, 'pnpm', 'fixture-package-1.2.3', 'COPYRIGHT'), 'utf8'),
    'Fixture copyright notice.\n',
  )
  assert.equal(
    await readFile(
      path.join(output, 'pnpm', 'fixture-package-1.2.3', 'ThirdPartyNoticeText.txt'),
      'utf8',
    ),
    'Fixture third-party notice.\n',
  )
  if (process.platform !== 'win32') {
    const bundleStat = await stat(path.join(output, 'pnpm'))
    const packageStat = await stat(path.join(output, 'pnpm', 'fixture-package-1.2.3'))
    assert.equal(bundleStat.mode & 0o777, 0o755)
    assert.equal(packageStat.mode & 0o777, 0o755)
  }
})

test('walks Cargo production and build dependencies but excludes dev-only dependencies', async (t) => {
  const output = await temporaryDirectory(t)
  const metadata = await fixtureJson('cargo-dependency-kinds.json')
  assert.equal(await generateCargoBundle(metadata, output), 2)

  const entries = await readdir(path.join(output, 'cargo'), { withFileTypes: true })
  const packageDirectories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.deepEqual(packageDirectories, ['build-dependency-2.0.0', 'normal-dependency-1.0.0'])
})

test('includes selected frontend build tools but excludes test-only dependencies', async (t) => {
  const output = await temporaryDirectory(t)
  const report = await fixtureJson('pnpm-build-dependencies.json')
  assert.equal(await generatePnpmBundle(report, output, ['fixture-build-tool']), 3)

  const packageDirectories = (await readdir(path.join(output, 'pnpm'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.deepEqual(packageDirectories, [
    'fixture-build-runtime-1.0.0',
    'fixture-build-tool-1.0.0',
    'fixture-package-1.2.3',
  ])
})

test(
  'rejects a symbolic-link output root without deleting its target',
  { skip: process.platform === 'win32' },
  async (t) => {
    const temporary = await temporaryDirectory(t)
    const target = path.join(temporary, 'target')
    const output = path.join(temporary, 'output-link')
    await mkdir(path.join(target, 'pnpm'), { recursive: true })
    const sentinel = path.join(target, 'pnpm', 'sentinel')
    await writeFile(sentinel, 'keep\n')
    await symlink(target, output, 'dir')
    const report = await fixtureJson('pnpm-duplicate.json')

    await assert.rejects(generatePnpmBundle(report, output, []), /must not be a symbolic link/)
    assert.equal(await readFile(sentinel, 'utf8'), 'keep\n')
  },
)
