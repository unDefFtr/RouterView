#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises'

const [cargoPath, pnpmPath, outputPath] = process.argv.slice(2)

if (!cargoPath || !pnpmPath || !outputPath) {
  console.error(
    'usage: generate-third-party-notices.mjs <cargo-metadata.json> <pnpm-licenses.json> <output.md>',
  )
  process.exit(2)
}

function fail(message) {
  console.error(message)
  process.exit(1)
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`)
  }
}

const [cargoMetadata, pnpmLicenses] = await Promise.all([
  readJson(cargoPath, 'Cargo metadata'),
  readJson(pnpmPath, 'pnpm license report'),
])

if (!isRecord(cargoMetadata) || !Array.isArray(cargoMetadata.packages)) {
  fail('Cargo metadata must contain a packages array')
}
if (!isRecord(pnpmLicenses)) {
  fail('pnpm license report must be an object keyed by license')
}
if ('error' in pnpmLicenses) {
  const detail = isRecord(pnpmLicenses.error)
    ? pnpmLicenses.error.message ?? pnpmLicenses.error.code ?? 'unknown error'
    : String(pnpmLicenses.error)
  fail(`pnpm license report contains an error: ${detail}`)
}

const cargoPackages = cargoMetadata.packages.flatMap((pkg, index) => {
    if (!isRecord(pkg) || typeof pkg.name !== 'string' || typeof pkg.version !== 'string') {
      fail(`Cargo package at index ${index} is missing a string name or version`)
    }
    if (pkg.source === null) return []
    if (typeof pkg.source !== 'string') {
      fail(`Cargo package ${pkg.name} has an invalid source`)
    }
    return [{
      ecosystem: 'Cargo',
      name: pkg.name,
      version: pkg.version,
      license: typeof pkg.license === 'string' ? pkg.license : 'UNKNOWN',
      source: pkg.repository ?? pkg.source,
    }]
  })

const pnpmPackages = Object.entries(pnpmLicenses).flatMap(([license, entries]) => {
  if (license.length === 0 || !Array.isArray(entries)) {
    fail(`pnpm license entry ${JSON.stringify(license)} must be a non-empty array`)
  }
  return entries.flatMap((pkg, index) => {
    if (!isRecord(pkg) || typeof pkg.name !== 'string' || pkg.name.length === 0) {
      fail(`pnpm package ${license}[${index}] is missing a string name`)
    }
    const versions = pkg.versions ?? (pkg.version === undefined ? [] : [pkg.version])
    if (!Array.isArray(versions) || versions.length === 0) {
      fail(`pnpm package ${pkg.name} has no versions`)
    }
    return versions.map((version) => {
      if (typeof version !== 'string') {
        fail(`pnpm package ${pkg.name} contains a non-string version`)
      }
      const repository = isRecord(pkg.repository) ? pkg.repository.url : pkg.repository
      return {
        ecosystem: 'pnpm',
        name: pkg.name,
        version,
        license,
        source: pkg.homepage ?? repository ?? '',
      }
    })
  })
})

if (cargoPackages.length === 0) fail('Cargo metadata contains no third-party packages')
if (pnpmPackages.length === 0) fail('pnpm license report contains no packages')

const packageMap = new Map()
for (const pkg of [...cargoPackages, ...pnpmPackages]) {
  packageMap.set(`${pkg.ecosystem}\0${pkg.name}\0${pkg.version}\0${pkg.license}`, pkg)
}
const packages = [...packageMap.values()].sort((left, right) => {
  const leftKey = `${left.ecosystem}:${left.name}:${left.version}`
  const rightKey = `${right.ecosystem}:${right.name}:${right.version}`
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
})

const unknown = packages.filter((pkg) => pkg.license === 'UNKNOWN')
if (unknown.length > 0) {
  console.error(
    `dependency license metadata is missing for: ${unknown
      .map((pkg) => `${pkg.ecosystem}:${pkg.name}@${pkg.version}`)
      .join(', ')}`,
  )
  process.exit(1)
}

const escapeCell = (value) => String(value)
  .replaceAll('|', '\\|')
  .replaceAll('\r', ' ')
  .replaceAll('\n', ' ')
const rows = packages.map(
  (pkg) =>
    `| ${escapeCell(pkg.ecosystem)} | ${escapeCell(pkg.name)} | ${escapeCell(pkg.version)} | ${escapeCell(pkg.license)} | ${escapeCell(pkg.source)} |`,
)

const document = `# Third-Party Dependency Inventory

This inventory is generated from the locked Cargo and pnpm dependency graphs. It
is a metadata index, not a replacement for the license texts shipped by each
dependency.

| Ecosystem | Package | Version | Declared license | Source |
|---|---|---:|---|---|
${rows.join('\n')}
`

await writeFile(outputPath, document, 'utf8')
