const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const WebSocket = require('ws');

// Mirrors Tauri's BASE_DIR logic
const BASE_DIR = path.join(__dirname, '../safe_files/');

// ---------------------------------------------------------------------------
// Vulnerable IPC Handler (Mirroring Tauri's read_file)
// ---------------------------------------------------------------------------
ipcMain.handle('read_file', async (event, userPath) => {
    try {
        // VULNERABILITY: direct concatenation without canonicalization checks
        const fullPath = path.join(BASE_DIR, userPath);
        const data = await fs.readFile(fullPath, 'utf8');
        return data;
    } catch (e) {
        throw new Error(`Failed to read file: ${e.message}`);
    }
});

ipcMain.handle('fetch_url', async (event, url) => {
    try {
        // VULNERABILITY: Blindly fetching any URL (SSRF)
        const response = await fetch(url);
        const data = await response.text();
        return data;
    } catch (e) {
        throw new Error(`Request failed: ${e.message}`);
    }
});

ipcMain.handle('process_data', async (event, data) => {
    try {
        // VULNERABILITY: Blindly expecting certain types without validation (Type Confusion)
        // In Rust this would panic on .unwrap(). Let's see what JS does.
        const name = data.name.toUpperCase();
        const age = data.age + 1;
        const role = data.metadata.role;
        return `Processed: ${name}, Age: ${age}, Role: ${role}`;
    } catch (e) {
        throw new Error(`PANIC: ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
let mainWindow;

app.whenReady().then(async () => {
    mainWindow = new BrowserWindow({
        show: true,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            sandbox: false
        }
    });

    await mainWindow.loadFile('index.html');

    console.log("[*] Electron harness ready. Running payloads...");
    
    try {
        const payloadsData = await fs.readFile(path.join(__dirname, 'payloads.json'), 'utf8');
        const payloads = JSON.parse(payloadsData);

        for (const req of payloads) {
            const { command, args } = req;
            
            let safeArg = "";
            if (command === 'read_file') safeArg = JSON.stringify(args.path);
            else if (command === 'fetch_url') safeArg = JSON.stringify(args.url);
            else if (command === 'process_data') safeArg = JSON.stringify(args.data);
            
            const code = `require('electron').ipcRenderer.invoke('${command}', ${safeArg})`;
            
            try {
                const result = await mainWindow.webContents.executeJavaScript(code);
                console.log(`\n[SUCCESS] ${command} | Payload: ${safeArg}`);
                console.log(`  -> Result: ${String(result).substring(0, 80).replace(/\\n/g, ' ')}`);
            } catch (err) {
                console.log(`\n[ERROR] ${command} | Payload: ${safeArg}`);
                console.log(`  -> ${err.message}`);
            }
        }
    } catch (e) {
        console.error("Test execution error:", e);
    }
    
    console.log("[*] Testing complete. Exiting...");
    app.quit();
});

app.on('window-all-closed', () => {
    app.quit();
});
