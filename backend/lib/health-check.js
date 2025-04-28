const os = require('os');
const { MongoClient } = require('mongodb');
const { config } = require('../config/env');

async function checkDatabaseConnection() {
  try {
    const client = await MongoClient.connect(config.MONGO_URL, {
      serverSelectionTimeoutMS: 5000
    });
    await client.close();
    return { status: 'healthy', message: 'Database connection successful' };
  } catch (error) {
    return { status: 'unhealthy', message: 'Database connection failed', error: error.message };
  }
}

function checkSystemResources() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;
  const memoryUsage = (usedMemory / totalMemory) * 100;
  
  const cpuLoad = os.loadavg()[0];
  const cpuCount = os.cpus().length;
  const normalizedCpuLoad = (cpuLoad / cpuCount) * 100;
  
  return {
    memory: {
      status: memoryUsage > 90 ? 'warning' : 'healthy',
      usage: Math.round(memoryUsage),
      total: Math.round(totalMemory / 1024 / 1024),
      free: Math.round(freeMemory / 1024 / 1024)
    },
    cpu: {
      status: normalizedCpuLoad > 80 ? 'warning' : 'healthy',
      load: Math.round(normalizedCpuLoad),
      cores: cpuCount
    }
  };
}

async function getHealthStatus() {
  const startTime = process.hrtime();
  
  const [dbHealth, sysResources] = await Promise.all([
    checkDatabaseConnection(),
    Promise.resolve(checkSystemResources())
  ]);
  
  const [seconds, nanoseconds] = process.hrtime(startTime);
  const responseTime = seconds * 1000 + nanoseconds / 1000000;
  
  return {
    status: dbHealth.status === 'healthy' ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    uptime: Math.round(process.uptime()),
    responseTime: Math.round(responseTime),
    database: dbHealth,
    system: sysResources,
    version: process.env.npm_package_version || '0.1.0',
    environment: config.NODE_ENV
  };
}

module.exports = {
  getHealthStatus
}; 