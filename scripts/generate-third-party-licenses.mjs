#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const LEGAL_FILE_PREFIX =
  /^(?:LICEN[CS]E|NOTICE|COPYING|COPYRIGHT|UNLICENSE|THIRD[-_. ]?PARTY|PATENTS?)/i
const MAX_LICENSE_BYTES = 16 * 1024 * 1024
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024
const MAX_PNPM_NODES = 100_000
const FRONTEND_BUNDLED_BUILD_DEPENDENCIES = ['@vitejs/plugin-vue', 'typescript', 'vite']

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requireNonEmptyString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`${label} must be a non-empty string without NUL bytes`)
  }
  return value
}

function validatePackageIdentity(name, version, label) {
  requireNonEmptyString(name, `${label} name`)
  requireNonEmptyString(version, `${label} version`)
  if (/\p{Cc}/u.test(name) || /\p{Cc}/u.test(version)) {
    throw new Error(`${label} name and version must not contain control characters`)
  }
}

function packageKey(name, version) {
  return `${name}\0${version}`
}

function safePathComponent(value) {
  const bytes = Buffer.from(value, 'utf8')
  let encoded = ''
  for (const byte of bytes) {
    const isAlphaNumeric =
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a)
    if (isAlphaNumeric || byte === 0x2d || byte === 0x2e || byte === 0x5f) {
      encoded += String.fromCharCode(byte)
    } else {
      encoded += `~${byte.toString(16).padStart(2, '0')}`
    }
  }
  if (encoded === '' || encoded === '.' || encoded === '..') {
    throw new Error(`cannot create a safe path component from ${JSON.stringify(value)}`)
  }
  if (encoded.length <= 160) return encoded
  const digest = createHash('sha256').update(value).digest('hex').slice(0, 20)
  return `${encoded.slice(0, 130)}--${digest}`
}

function packageDirectoryName(name, version) {
  return `${safePathComponent(name)}-${safePathComponent(version)}`
}

function validateCargoMetadata(metadata, rootPackageName) {
  if (!isRecord(metadata) || !Array.isArray(metadata.packages)) {
    throw new Error('Cargo metadata must contain a packages array')
  }
  if (!isRecord(metadata.resolve) || !Array.isArray(metadata.resolve.nodes)) {
    throw new Error('Cargo metadata must contain a resolved dependency graph')
  }
  if (!Array.isArray(metadata.workspace_members)) {
    throw new Error('Cargo metadata must contain workspace_members')
  }

  const packages = new Map()
  for (const [index, pkg] of metadata.packages.entries()) {
    if (!isRecord(pkg)) throw new Error(`Cargo package at index ${index} must be an object`)
    const id = requireNonEmptyString(pkg.id, `Cargo package at index ${index} id`)
    validatePackageIdentity(pkg.name, pkg.version, `Cargo package ${id}`)
    requireNonEmptyString(pkg.manifest_path, `Cargo package ${pkg.name} manifest_path`)
    if (packages.has(id)) throw new Error(`Cargo metadata contains duplicate package id ${id}`)
    packages.set(id, pkg)
  }

  const workspaceMembers = new Set(
    metadata.workspace_members.map((id, index) =>
      requireNonEmptyString(id, `Cargo workspace member at index ${index}`),
    ),
  )
  const roots = [...workspaceMembers].filter((id) => packages.get(id)?.name === rootPackageName)
  if (roots.length !== 1) {
    throw new Error(
      `Cargo metadata must contain exactly one workspace package named ${rootPackageName}; found ${roots.length}`,
    )
  }

  const nodes = new Map()
  for (const [index, node] of metadata.resolve.nodes.entries()) {
    if (!isRecord(node)) throw new Error(`Cargo resolve node at index ${index} must be an object`)
    const id = requireNonEmptyString(node.id, `Cargo resolve node at index ${index} id`)
    if (!Array.isArray(node.deps)) throw new Error(`Cargo resolve node ${id} must contain deps`)
    if (nodes.has(id)) throw new Error(`Cargo metadata contains duplicate resolve node ${id}`)
    nodes.set(id, node)
  }

  return { packages, workspaceMembers, nodes, rootId: roots[0] }
}

export function collectCargoDependencies(metadata, rootPackageName = 'routerview-backend') {
  const { packages, workspaceMembers, nodes, rootId } = validateCargoMetadata(
    metadata,
    rootPackageName,
  )
  const pending = [rootId]
  const visited = new Set([rootId])

  while (pending.length > 0) {
    const id = pending.pop()
    const node = nodes.get(id)
    if (!node) throw new Error(`Cargo dependency graph is missing resolve node ${id}`)

    for (const [index, dependency] of node.deps.entries()) {
      if (!isRecord(dependency)) {
        throw new Error(`Cargo dependency ${id}[${index}] must be an object`)
      }
      const dependencyId = requireNonEmptyString(
        dependency.pkg,
        `Cargo dependency ${id}[${index}] package id`,
      )
      if (!Array.isArray(dependency.dep_kinds) || dependency.dep_kinds.length === 0) {
        throw new Error(`Cargo dependency ${id} -> ${dependencyId} must contain dep_kinds`)
      }
      let isProduction = false
      for (const [kindIndex, kind] of dependency.dep_kinds.entries()) {
        if (!isRecord(kind)) {
          throw new Error(
            `Cargo dependency kind ${id} -> ${dependencyId}[${kindIndex}] must be an object`,
          )
        }
        if (![null, 'normal', 'build', 'dev'].includes(kind.kind)) {
          throw new Error(
            `Cargo dependency ${id} -> ${dependencyId} has unsupported kind ${JSON.stringify(kind.kind)}`,
          )
        }
        if (kind.kind !== 'dev') isProduction = true
      }
      if (!isProduction || visited.has(dependencyId)) continue
      if (!packages.has(dependencyId)) {
        throw new Error(`Cargo dependency graph references unknown package ${dependencyId}`)
      }
      visited.add(dependencyId)
      pending.push(dependencyId)
    }
  }

  return [...visited]
    .filter((id) => id !== rootId && !workspaceMembers.has(id))
    .map((id) => {
      const pkg = packages.get(id)
      return {
        identity: id,
        name: pkg.name,
        version: pkg.version,
        declaredLicense: typeof pkg.license === 'string' ? pkg.license : 'UNKNOWN',
        manifestPath: pkg.manifest_path,
      }
    })
}

function dependencyContainers(node, label, rootBuildDependencies) {
  const result = []
  for (const field of ['dependencies', 'optionalDependencies']) {
    if (node[field] === undefined) continue
    if (!isRecord(node[field])) throw new Error(`${label} ${field} must be an object`)
    result.push([field, node[field]])
  }
  if (rootBuildDependencies.length > 0) {
    if (!isRecord(node.devDependencies)) {
      throw new Error(`${label} must contain devDependencies for release build tools`)
    }
    const selected = {}
    for (const name of rootBuildDependencies) {
      requireNonEmptyString(name, 'pnpm release build dependency name')
      if (!isRecord(node.devDependencies[name])) {
        throw new Error(`${label} is missing release build dependency ${name}`)
      }
      selected[name] = node.devDependencies[name]
    }
    result.push(['releaseBuildDependencies', selected])
  }
  return result
}

export function collectPnpmDependencies(
  report,
  rootBuildDependencies = FRONTEND_BUNDLED_BUILD_DEPENDENCIES,
) {
  if (!Array.isArray(report) || report.length === 0) {
    throw new Error('pnpm release dependency report must be a non-empty array')
  }

  const pending = []
  for (const [rootIndex, root] of report.entries()) {
    if (!isRecord(root)) throw new Error(`pnpm project at index ${rootIndex} must be an object`)
    pending.push({
      node: root,
      label: `pnpm project at index ${rootIndex}`,
      rootBuildDependencies,
    })
  }

  const dependencies = []
  let traversed = 0
  while (pending.length > 0) {
    const { node, label, rootBuildDependencies: buildDependencies = [] } = pending.pop()
    for (const [field, container] of dependencyContainers(node, label, buildDependencies)) {
      for (const [reportedName, dependency] of Object.entries(container)) {
        traversed += 1
        if (traversed > MAX_PNPM_NODES) {
          throw new Error(`pnpm dependency report exceeds ${MAX_PNPM_NODES} nodes`)
        }
        requireNonEmptyString(reportedName, `${label} ${field} dependency name`)
        if (!isRecord(dependency)) {
          throw new Error(`${label} ${field} dependency ${reportedName} must be an object`)
        }
        const version = requireNonEmptyString(
          dependency.version,
          `pnpm dependency ${reportedName} version`,
        )
        const packagePath = requireNonEmptyString(
          dependency.path,
          `pnpm dependency ${reportedName}@${version} path`,
        )
        if (!path.isAbsolute(packagePath)) {
          throw new Error(`pnpm dependency ${reportedName}@${version} path must be absolute`)
        }
        dependencies.push({
          reportedName,
          version,
          packagePath,
          resolved: typeof dependency.resolved === 'string' ? dependency.resolved : '',
        })
        pending.push({
          node: dependency,
          label: `pnpm dependency ${reportedName}@${version}`,
          rootBuildDependencies: [],
        })
      }
    }
  }
  if (dependencies.length === 0) {
    throw new Error('pnpm release dependency report contains no dependencies')
  }
  return dependencies
}

async function readRegularFile(filePath, maxBytes, label) {
  let handle
  try {
    handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const fileStat = await handle.stat()
    if (!fileStat.isFile()) throw new Error(`${label} is not a regular file`)
    if (fileStat.size > maxBytes) {
      throw new Error(`${label} exceeds the ${maxBytes}-byte limit`)
    }
    return await handle.readFile()
  } catch (error) {
    if (error?.code === 'ELOOP') throw new Error(`${label} must not be a symbolic link`)
    throw error
  } finally {
    await handle?.close()
  }
}

async function resolvePackageDirectory(inputPath, label) {
  const inputStat = await stat(inputPath).catch((error) => {
    throw new Error(`${label} is not accessible: ${error.message}`)
  })
  if (!inputStat.isDirectory()) throw new Error(`${label} is not a directory`)
  return realpath(inputPath)
}

async function readLicenseFiles(packageDirectory, packageLabel) {
  const entries = await readdir(packageDirectory, { withFileTypes: true })
  const matching = entries
    .filter((entry) => LEGAL_FILE_PREFIX.test(entry.name) && entry.isFile())
    .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  const destinationNames = new Map()
  const licenses = []

  for (const entry of matching) {
    const destinationName = safePathComponent(entry.name)
    const collisionKey = destinationName.toLocaleLowerCase('en')
    const previous = destinationNames.get(collisionKey)
    if (previous && previous !== entry.name) {
      throw new Error(
        `${packageLabel} has colliding license file names ${previous} and ${entry.name}`,
      )
    }
    destinationNames.set(collisionKey, entry.name)
    const contents = await readRegularFile(
      path.join(packageDirectory, entry.name),
      MAX_LICENSE_BYTES,
      `${packageLabel} license file ${entry.name}`,
    )
    if (contents.toString('utf8').trim().length === 0) {
      throw new Error(`${packageLabel} license file ${entry.name} is empty`)
    }
    licenses.push({
      sourceName: entry.name,
      destinationName,
      contents,
      sha256: createHash('sha256').update(contents).digest('hex'),
    })
  }
  if (licenses.length === 0) {
    throw new Error(
      `${packageLabel} has no recognized regular license or notice file in ${packageDirectory}`,
    )
  }
  return licenses
}

function licenseSetSignature(licenses) {
  return licenses.map((license) => `${license.destinationName}\0${license.sha256}`).join('\0')
}

async function prepareCargoPackages(dependencies) {
  const prepared = []
  for (const dependency of dependencies) {
    if (!path.isAbsolute(dependency.manifestPath)) {
      throw new Error(`Cargo package ${dependency.name}@${dependency.version} manifest_path must be absolute`)
    }
    const manifestStat = await lstat(dependency.manifestPath).catch((error) => {
      throw new Error(
        `Cargo package ${dependency.name}@${dependency.version} manifest is not accessible: ${error.message}`,
      )
    })
    if (!manifestStat.isFile()) {
      throw new Error(`Cargo package ${dependency.name}@${dependency.version} manifest is not a regular file`)
    }
    const packageDirectory = await resolvePackageDirectory(
      path.dirname(dependency.manifestPath),
      `Cargo package ${dependency.name}@${dependency.version} directory`,
    )
    const packageLabel = `Cargo package ${dependency.name}@${dependency.version}`
    prepared.push({
      ...dependency,
      packageDirectory,
      licenses: await readLicenseFiles(packageDirectory, packageLabel),
    })
  }
  return prepared
}

function declaredPnpmLicense(manifest) {
  if (typeof manifest.license === 'string' && manifest.license.length > 0) return manifest.license
  if (Array.isArray(manifest.licenses)) {
    const licenses = manifest.licenses
      .map((license) => (typeof license === 'string' ? license : license?.type))
      .filter((license) => typeof license === 'string' && license.length > 0)
    if (licenses.length > 0) return licenses.join(' OR ')
  }
  return 'UNKNOWN'
}

async function preparePnpmPackages(dependencies) {
  const prepared = []
  for (const dependency of dependencies) {
    const packageDirectory = await resolvePackageDirectory(
      dependency.packagePath,
      `pnpm dependency ${dependency.reportedName}@${dependency.version} directory`,
    )
    const manifestPath = path.join(packageDirectory, 'package.json')
    const manifestContents = await readRegularFile(
      manifestPath,
      MAX_MANIFEST_BYTES,
      `pnpm dependency ${dependency.reportedName}@${dependency.version} package.json`,
    ).catch((error) => {
      throw new Error(error.message)
    })
    let manifest
    try {
      manifest = JSON.parse(manifestContents.toString('utf8'))
    } catch (error) {
      throw new Error(
        `pnpm dependency ${dependency.reportedName}@${dependency.version} package.json is not valid JSON: ${error.message}`,
      )
    }
    if (!isRecord(manifest)) {
      throw new Error(`pnpm dependency ${dependency.reportedName}@${dependency.version} package.json must be an object`)
    }
    validatePackageIdentity(manifest.name, manifest.version, 'pnpm package manifest')
    if (manifest.version !== dependency.version) {
      throw new Error(
        `pnpm dependency ${dependency.reportedName} reports version ${dependency.version}, but its package.json reports ${manifest.version}`,
      )
    }
    const packageLabel = `pnpm package ${manifest.name}@${manifest.version}`
    prepared.push({
      identity: `${manifest.name}@${manifest.version}:${dependency.resolved}`,
      name: manifest.name,
      version: manifest.version,
      declaredLicense: declaredPnpmLicense(manifest),
      packageDirectory,
      resolved: dependency.resolved,
      licenses: await readLicenseFiles(packageDirectory, packageLabel),
    })
  }
  return prepared
}

function deduplicatePackages(packages, ecosystem) {
  const deduplicated = new Map()
  for (const pkg of packages) {
    const key = packageKey(pkg.name, pkg.version)
    const existing = deduplicated.get(key)
    if (!existing) {
      deduplicated.set(key, pkg)
      continue
    }
    if (ecosystem === 'cargo' && existing.identity !== pkg.identity) {
      throw new Error(
        `Cargo output collision: ${pkg.name}@${pkg.version} resolves to multiple package ids`,
      )
    }
    if (existing.resolved && pkg.resolved && existing.resolved !== pkg.resolved) {
      throw new Error(
        `pnpm output collision: ${pkg.name}@${pkg.version} resolves to multiple sources`,
      )
    }
    if (licenseSetSignature(existing.licenses) !== licenseSetSignature(pkg.licenses)) {
      throw new Error(
        `${ecosystem} duplicate ${pkg.name}@${pkg.version} has inconsistent license files`,
      )
    }
  }
  return [...deduplicated.values()].sort((left, right) => {
    const leftKey = `${left.name}\0${left.version}`
    const rightKey = `${right.name}\0${right.version}`
    return leftKey.localeCompare(rightKey, 'en')
  })
}

function escapeMarkdownCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\r', ' ').replaceAll('\n', ' ')
}

function dependencyIndex(packages, ecosystem) {
  const heading = ecosystem === 'cargo' ? 'Cargo' : 'pnpm'
  const rows = packages.map((pkg) => {
    const directory = packageDirectoryName(pkg.name, pkg.version)
    const files = pkg.licenses.map((license) => license.destinationName).join(', ')
    return `| ${escapeMarkdownCell(pkg.name)} | ${escapeMarkdownCell(pkg.version)} | ${escapeMarkdownCell(pkg.declaredLicense)} | ${escapeMarkdownCell(directory)} | ${escapeMarkdownCell(files)} |`
  })
  return `# ${heading} Third-Party Licenses

This directory contains verbatim license, notice, copyright, and related legal
files from the locked release dependency graph. It contains ${packages.length}
unique packages.

| Package | Version | Declared license | Directory | Files |
|---|---:|---|---|---|
${rows.join('\n')}
`
}

async function writeEcosystemBundle(packages, ecosystem, outputRoot) {
  const requestedRoot = path.resolve(outputRoot)
  await mkdir(requestedRoot, { recursive: true })
  const requestedRootStat = await lstat(requestedRoot)
  if (requestedRootStat.isSymbolicLink()) {
    throw new Error(`license output root must not be a symbolic link: ${requestedRoot}`)
  }
  if (!requestedRootStat.isDirectory()) {
    throw new Error(`license output root is not a directory: ${requestedRoot}`)
  }
  const root = await realpath(requestedRoot)
  await chmod(root, 0o755)
  const temporary = await mkdtemp(path.join(root, `.${ecosystem}-licenses-`))
  try {
    await chmod(temporary, 0o755)
    const destinations = new Map()
    for (const pkg of packages) {
      const directoryName = packageDirectoryName(pkg.name, pkg.version)
      const collisionKey = directoryName.toLocaleLowerCase('en')
      const identity = packageKey(pkg.name, pkg.version)
      const previous = destinations.get(collisionKey)
      if (previous && previous !== identity) {
        throw new Error(
          `${ecosystem} output path collision between ${previous.replace('\0', '@')} and ${pkg.name}@${pkg.version}`,
        )
      }
      destinations.set(collisionKey, identity)
      const packageOutput = path.join(temporary, directoryName)
      await mkdir(packageOutput)
      await chmod(packageOutput, 0o755)
      for (const license of pkg.licenses) {
        await writeFile(path.join(packageOutput, license.destinationName), license.contents, {
          flag: 'wx',
          mode: 0o644,
        })
      }
    }
    await writeFile(path.join(temporary, 'DEPENDENCIES.md'), dependencyIndex(packages, ecosystem), {
      flag: 'wx',
      mode: 0o644,
    })
    const destination = path.join(root, ecosystem)
    const destinationStat = await lstat(destination).catch((error) => {
      if (error?.code === 'ENOENT') return null
      throw error
    })
    if (destinationStat?.isSymbolicLink()) {
      throw new Error(`license output destination must not be a symbolic link: ${destination}`)
    }
    if (destinationStat && !destinationStat.isDirectory()) {
      throw new Error(`license output destination is not a directory: ${destination}`)
    }
    await rm(destination, { recursive: true, force: true })
    await rename(temporary, destination)
  } catch (error) {
    await rm(temporary, { recursive: true, force: true })
    throw error
  }
  return packages.length
}

export async function generateCargoBundle(metadata, outputRoot, rootPackageName = 'routerview-backend') {
  const dependencies = collectCargoDependencies(metadata, rootPackageName)
  if (dependencies.length === 0) throw new Error('Cargo production dependency graph is empty')
  const packages = deduplicatePackages(await prepareCargoPackages(dependencies), 'cargo')
  return writeEcosystemBundle(packages, 'cargo', outputRoot)
}

export async function generatePnpmBundle(
  report,
  outputRoot,
  rootBuildDependencies = FRONTEND_BUNDLED_BUILD_DEPENDENCIES,
) {
  const dependencies = collectPnpmDependencies(report, rootBuildDependencies)
  const packages = deduplicatePackages(await preparePnpmPackages(dependencies), 'pnpm')
  return writeEcosystemBundle(packages, 'pnpm', outputRoot)
}

async function readJson(inputPath, label) {
  let contents
  try {
    contents = await readFile(inputPath, 'utf8')
  } catch (error) {
    throw new Error(`${label} cannot be read: ${error.message}`)
  }
  try {
    return JSON.parse(contents)
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`)
  }
}

async function main() {
  const [ecosystem, inputPath, outputRoot, ...extra] = process.argv.slice(2)
  if (!['cargo', 'pnpm'].includes(ecosystem) || !inputPath || !outputRoot || extra.length > 0) {
    console.error(
      'usage: generate-third-party-licenses.mjs <cargo|pnpm> <dependency-report.json> <output-root>',
    )
    process.exitCode = 2
    return
  }
  const report = await readJson(
    inputPath,
    ecosystem === 'cargo' ? 'Cargo metadata' : 'pnpm release dependency report',
  )
  const count =
    ecosystem === 'cargo'
      ? await generateCargoBundle(report, outputRoot)
      : await generatePnpmBundle(report, outputRoot)
  console.log(`Bundled licenses for ${count} unique ${ecosystem} dependencies`)
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
