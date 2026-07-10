#!/usr/bin/env node

import { readFile } from 'node:fs/promises'

const [tag, cargoMetadataPath, frontendPackagePath] = process.argv.slice(2)

if (!tag || !cargoMetadataPath || !frontendPackagePath) {
  console.error(
    'usage: verify-release-version.mjs <tag> <cargo-metadata.json> <frontend-package.json>',
  )
  process.exit(2)
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    console.error(`${label} is not valid JSON: ${error.message}`)
    process.exit(1)
  }
}

const [cargoMetadata, frontendPackage] = await Promise.all([
  readJson(cargoMetadataPath, 'Cargo metadata'),
  readJson(frontendPackagePath, 'frontend package'),
])

const backendPackages = Array.isArray(cargoMetadata.packages)
  ? cargoMetadata.packages.filter((pkg) => pkg?.name === 'routerview-backend')
  : []
if (backendPackages.length !== 1 || typeof backendPackages[0].version !== 'string') {
  console.error('Cargo metadata must contain exactly one routerview-backend package')
  process.exit(1)
}
if (frontendPackage?.name !== 'routerview-frontend' || typeof frontendPackage.version !== 'string') {
  console.error('frontend package must be routerview-frontend with a string version')
  process.exit(1)
}

const backendVersion = backendPackages[0].version
const frontendVersion = frontendPackage.version
const expectedTag = `v${backendVersion}`
if (frontendVersion !== backendVersion || tag !== expectedTag) {
  console.error(
    `release version mismatch: tag=${tag}, backend=${backendVersion}, frontend=${frontendVersion}; expected tag ${expectedTag}`,
  )
  process.exit(1)
}

console.log(`Release version verified: ${tag}`)
