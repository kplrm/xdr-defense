const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const versionFile = path.join(rootDir, 'VERSION');
const packageFile = path.join(rootDir, 'package.json');
const manifestFile = path.join(rootDir, 'opensearch_dashboards.json');

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

const version = fs.readFileSync(versionFile, 'utf8').trim();

if (!version) {
  throw new Error('VERSION file is empty');
}

const packageJson = readJson(packageFile);
const manifestJson = readJson(manifestFile);
let changed = false;

if (packageJson.version !== version) {
  packageJson.version = version;
  writeJson(packageFile, packageJson);
  changed = true;
}

if (manifestJson.version !== version) {
  manifestJson.version = version;
  writeJson(manifestFile, manifestJson);
  changed = true;
}

if (changed) {
  console.log(`Synchronized package metadata to VERSION=${version}`);
} else {
  console.log(`Version metadata already synchronized: ${version}`);
}
