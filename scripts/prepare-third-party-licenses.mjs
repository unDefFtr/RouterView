#!/usr/bin/env node

import { execFile as execFileCallback } from 'node:child_process'
import { promisify } from 'node:util'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  generateCargoBundle,
  generatePnpmBundle,
} from './generate-third-party-licenses.mjs'

const execFile = promisify(execFileCallback)
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function usage() {
  console.error(`usage: prepare-third-party-licenses.mjs [options]

Options:
  --output <path>        output root for both ecosystems (default: third-party-licenses)
  --cargo-output <path>  output root for Cargo licenses
  --pnpm-output <path>   output root for pnpm licenses
  --target <triple>      Cargo filter platform (default: rustc host triple)`)
}

function parseArguments(args) {
  const options = {}
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]
    if (!['--output', '--cargo-output', '--pnpm-output', '--target'].includes(argument)) {
      throw new Error(`unknown option ${argument}`)
    }
    const value = args[index + 1]
    if (!value || value.startsWith('--')) throw new Error(`${argument} requires a value`)
    options[argument.slice(2)] = value
    index += 1
  }
  const commonOutput = options.output ?? path.join(repositoryRoot, 'third-party-licenses')
  return {
    cargoOutput: path.resolve(options['cargo-output'] ?? commonOutput),
    pnpmOutput: path.resolve(options['pnpm-output'] ?? commonOutput),
    target: options.target,
  }
}

async function commandJson(command, args, label) {
  let stdout
  try {
    ;({ stdout } = await execFile(command, args, {
      cwd: repositoryRoot,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    }))
  } catch (error) {
    const detail = error.stderr?.trim() || error.message
    throw new Error(`${label} failed: ${detail}`)
  }
  try {
    return JSON.parse(stdout)
  } catch (error) {
    throw new Error(`${label} returned invalid JSON: ${error.message}`)
  }
}

async function rustHostTriple() {
  let stdout
  try {
    ;({ stdout } = await execFile('rustc', ['-vV'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
    }))
  } catch (error) {
    throw new Error(`cannot determine the rustc host triple: ${error.message}`)
  }
  const host = stdout.match(/^host: (.+)$/m)?.[1]
  if (!host) throw new Error('rustc -vV did not report a host triple')
  return host
}

async function main() {
  let options
  try {
    options = parseArguments(process.argv.slice(2))
  } catch (error) {
    usage()
    throw error
  }
  const target = options.target ?? (await rustHostTriple())
  const [cargoMetadata, pnpmReport] = await Promise.all([
    commandJson(
      'cargo',
      ['metadata', '--locked', '--format-version', '1', '--filter-platform', target],
      'cargo metadata',
    ),
    commandJson(
      'pnpm',
      ['--dir', 'frontend', 'list', '--json', '--depth', 'Infinity', '--no-optional'],
      'pnpm release dependency listing',
    ),
  ])
  const cargoCount = await generateCargoBundle(cargoMetadata, options.cargoOutput)
  const pnpmCount = await generatePnpmBundle(pnpmReport, options.pnpmOutput)
  console.log(
    `Bundled ${cargoCount} Cargo and ${pnpmCount} pnpm dependencies for ${target}`,
  )
}

main().catch((error) => {
  console.error(error.message)
  process.exitCode = 1
})
