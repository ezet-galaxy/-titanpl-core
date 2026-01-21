const fs = require('fs');
const path = require('path');
const os = require('os');

const platform = os.platform(); // 'win32', 'linux', 'darwin'
const titanConfigPath = path.resolve(__dirname, 'titan.json');

console.log(`Configuring titan.json for platform: ${platform}`);

try {
    const content = fs.readFileSync(titanConfigPath, 'utf8');
    const titanConfig = JSON.parse(content);

    let libPath = "";
    if (platform === 'win32') {
        libPath = "native/target/release/titan_core.dll";
    } else if (platform === 'darwin') {
        libPath = "native/target/release/libtitan_core.dylib";
    } else {
        // Assume linux/unix defaults for anything else
        libPath = "native/target/release/libtitan_core.so";
    }

    const fullPath = path.resolve(__dirname, libPath);
    if (!fs.existsSync(fullPath)) {
        console.warn(`Warning: Native binary not found at ${fullPath}. Valid binaries for this platform must be built or provided.`);
    }

    // Check if configuration actually needs changing to avoid unnecessary writes
    if (titanConfig.native && titanConfig.native.path === libPath) {
        console.log(`titan.json is already configured for ${platform}.`);
        process.exit(0);
    }

    if (!titanConfig.native) {
        titanConfig.native = {};
    }

    titanConfig.native.path = libPath;

    fs.writeFileSync(titanConfigPath, JSON.stringify(titanConfig, null, 2));
    console.log(`Successfully updated titan.json native path to: ${libPath}`);
} catch (error) {
    console.error("Error configuring titan.json:", error);
    process.exit(1);
}
