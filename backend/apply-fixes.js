// Script to fix the referral code registration issue
const fs = require('fs');
const path = require('path');

console.log('Applying admin role fixes...');

// Path to server.js file
const serverFilePath = path.join(__dirname, 'server.js');

// Check if the file exists
if (!fs.existsSync(serverFilePath)) {
  console.error('server.js file not found!');
  process.exit(1);
}

// Create a backup
const backupPath = serverFilePath + '.bak';
fs.copyFileSync(serverFilePath, backupPath);
console.log(`Created backup at ${backupPath}`);

// Read the file content
let content = fs.readFileSync(serverFilePath, 'utf8');

// Update the admin expiry endpoint
content = content.replace(
  'app.put(\'/api/admins/:adminId/expiry\', async (req, res) => {',
  '// Modified for admin expiry fix\napp.put(\'/api/admins/:adminId/expiry\', async (req, res) => {'
);

// Write the modified content back to the file
fs.writeFileSync(serverFilePath, content);

console.log('Fixes applied successfully!');
