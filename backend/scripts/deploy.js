const { validateEnv } = require('../config/env');
const { getHealthStatus } = require('../lib/health-check');
const fs = require('fs').promises;
const path = require('path');

async function checkPreDeployment() {
  console.log('Running pre-deployment checks...\n');
  
  // Check environment variables
  try {
    console.log('Validating environment variables...');
    validateEnv();
    console.log('✓ Environment variables are valid\n');
  } catch (error) {
    console.error('✗ Environment variable validation failed:', error.message);
    process.exit(1);
  }
  
  // Check if all required files exist
  const requiredFiles = [
    'server.js',
    'package.json',
    'vercel.json',
    'database.js'
  ];
  
  console.log('Checking required files...');
  for (const file of requiredFiles) {
    try {
      await fs.access(path.join(__dirname, '..', file));
      console.log(`✓ Found ${file}`);
    } catch (error) {
      console.error(`✗ Missing required file: ${file}`);
      process.exit(1);
    }
  }
  console.log('');
  
  // Check package.json scripts
  const packageJson = require('../package.json');
  const requiredScripts = ['start', 'build', 'vercel-build'];
  
  console.log('Checking package.json scripts...');
  for (const script of requiredScripts) {
    if (!packageJson.scripts[script]) {
      console.error(`✗ Missing required script in package.json: ${script}`);
      process.exit(1);
    }
    console.log(`✓ Found script: ${script}`);
  }
  console.log('');
  
  // Check system health
  try {
    console.log('Checking system health...');
    const health = await getHealthStatus();
    
    if (health.status === 'healthy') {
      console.log('✓ System health check passed');
      console.log(`  - Database: ${health.database.status}`);
      console.log(`  - Memory usage: ${health.system.memory.usage}%`);
      console.log(`  - CPU load: ${health.system.cpu.load}%`);
    } else {
      console.error('✗ System health check failed');
      console.error(JSON.stringify(health, null, 2));
      process.exit(1);
    }
  } catch (error) {
    console.error('✗ Failed to check system health:', error.message);
    process.exit(1);
  }
  
  console.log('\n✓ All pre-deployment checks passed!');
}

// Run the checks
checkPreDeployment().catch(error => {
  console.error('Pre-deployment checks failed:', error);
  process.exit(1);
}); 