import { readFileSync, existsSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { platform as _platform } from 'os';
import { spawnSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const platform = _platform();
const titanConfigPath = resolve(__dirname, 'titan.json');

console.log(`Configuring titan.json for platform: ${platform}`);

// 1. Platform-specific output file name
let libFile = "";
if (platform === "win32") {
    libFile = "titan_core.dll";
} else if (platform === "darwin") {
    libFile = "libtitan_core.dylib";
} else {
    libFile = "libtitan_core.so";
}

const nativeDir = resolve(__dirname, "native");
const expectedBinary = resolve(nativeDir, "target/release", libFile);

// 2. Build if binary missing
if (!existsSync(expectedBinary)) {
    console.log(`Native binary missing.`);
}

// 3. Update titan.json
try {
    const content = readFileSync(titanConfigPath, "utf8");
    const titanConfig = JSON.parse(content);

    const relativeLibPath = `native/target/release/${libFile}`;

    if (!titanConfig.native) {
        titanConfig.native = {};
    }

    titanConfig.native.path = relativeLibPath;

    writeFileSync(titanConfigPath, JSON.stringify(titanConfig, null, 2));
    console.log(`Updated titan.json to use native binary: ${relativeLibPath}`);
} catch (error) {
    console.error("Error updating titan.json:", error);
    process.exit(1);
}
