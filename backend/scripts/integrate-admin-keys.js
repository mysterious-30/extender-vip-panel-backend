/**
 * Admin Keys Integration Script
 * 
 * This script helps integrate the admin-keys functionality into your server.js file.
 */

const fs = require('fs');
const path = require('path');

// Paths
const serverPath = path.join(__dirname, '..', 'server.js');
const backupPath = path.join(__dirname, '..', 'server.js.backup-' + Date.now());

// Main function
async function integrateAdminKeys() {
  console.log('Starting admin keys integration...');
  
  // 1. Backup original server.js
  console.log('Creating backup of server.js...');
  if (fs.existsSync(serverPath)) {
    fs.copyFileSync(serverPath, backupPath);
    console.log(`Backup created at: ${backupPath}`);
  } else {
    console.error('Error: server.js not found!');
    process.exit(1);
  }
  
  // 2. Read server.js
  console.log('Reading server.js...');
  let serverContent = fs.readFileSync(serverPath, 'utf8');
  
  // 3. Add import if not already present
  if (!serverContent.includes('const adminKeysRoutes = require')) {
    console.log('Adding adminKeysRoutes import...');
    
    // Find where other requires are and add our import there
    const requirePattern = /^const\s+\w+\s+=\s+require\(['"]\w+.*['"]\);/gm;
    const lastRequireMatch = [...serverContent.matchAll(requirePattern)].pop();
    
    if (lastRequireMatch) {
      const lastRequireIndex = lastRequireMatch.index + lastRequireMatch[0].length;
      serverContent = 
        serverContent.slice(0, lastRequireIndex) + 
        '\n\n// Import admin-keys routes\nconst adminKeysRoutes = require(\'./admin-keys\');\n' + 
        serverContent.slice(lastRequireIndex);
    } else {
      // Add at the top if no requires found
      serverContent = 
        '// Import admin-keys routes\nconst adminKeysRoutes = require(\'./admin-keys\');\n\n' +
        serverContent;
    }
  } else {
    console.log('adminKeysRoutes import already exists, skipping...');
  }
  
  // 4. Add route registration if not already present
  if (!serverContent.includes('app.use(\'/\', adminKeysRoutes)')) {
    console.log('Adding adminKeysRoutes registration...');
    
    // Find where to add the route registration (before the server start)
    const startServerPattern = /startServer\(\);/;
    const startServerMatch = serverContent.match(startServerPattern);
    
    if (startServerMatch) {
      const startServerIndex = startServerMatch.index;
      serverContent = 
        serverContent.slice(0, startServerIndex) + 
        '// Register admin keys routes\napp.use(\'/\', adminKeysRoutes);\n\n' + 
        serverContent.slice(startServerIndex);
    } else {
      // Add at the end if startServer not found
      serverContent += '\n\n// Register admin keys routes\napp.use(\'/\', adminKeysRoutes);\n';
    }
  } else {
    console.log('adminKeysRoutes registration already exists, skipping...');
  }
  
  // 5. Write the updated file
  console.log('Writing updated server.js...');
  fs.writeFileSync(serverPath, serverContent, 'utf8');
  
  console.log('\nIntegration completed successfully!');
  console.log('The admin-keys functionality is now integrated into your server.');
  console.log('Please restart your server to apply the changes.');
  console.log(`If anything goes wrong, you can restore from the backup at: ${backupPath}`);
}

// Run the integration
integrateAdminKeys().catch(err => {
  console.error('Error during integration:', err);
  console.log('Please restore from the backup and try again.');
}); 