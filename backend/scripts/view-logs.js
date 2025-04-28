#!/usr/bin/env node

/**
 * Error log viewer script
 * 
 * Usage:
 *   node scripts/view-logs.js [options]
 * 
 * Options:
 *   --level=<level>    Filter by log level (debug, info, warn, error, critical)
 *   --days=<days>      Show logs from the last X days (default: 1)
 *   --source=<source>  Filter by source (client, server, manual, etc.)
 *   --limit=<limit>    Limit number of results (default: 50)
 *   --search=<query>   Search in error messages
 *   --json             Output in JSON format
 *   --mongodb          Fetch logs from MongoDB (default: read from log files)
 *   --help             Show this help message
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { MongoClient } = require('mongodb');
const { connectToDatabase } = require('../lib/mongodb');

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  level: getArgValue(args, '--level') || null,
  days: parseInt(getArgValue(args, '--days') || '1', 10),
  source: getArgValue(args, '--source') || null,
  limit: parseInt(getArgValue(args, '--limit') || '50', 10),
  search: getArgValue(args, '--search') || null,
  json: args.includes('--json'),
  mongodb: args.includes('--mongodb'),
  help: args.includes('--help')
};

// Show help if requested
if (options.help) {
  console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(1, 18).join('\n'));
  process.exit(0);
}

// Main function
async function main() {
  try {
    if (options.mongodb) {
      await viewMongoDbLogs(options);
    } else {
      await viewFileSystemLogs(options);
    }
  } catch (error) {
    console.error('Error viewing logs:', error);
    process.exit(1);
  }
}

// View logs from MongoDB
async function viewMongoDbLogs(options) {
  console.log('Fetching logs from MongoDB...');
  
  try {
    const { db } = await connectToDatabase();
    
    // Prepare query
    const query = {};
    
    // Filter by level
    if (options.level) {
      query['level'] = options.level;
    }
    
    // Filter by date
    if (options.days) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - options.days);
      query['timestamp'] = { $gte: cutoffDate };
    }
    
    // Filter by source
    if (options.source) {
      query['metadata.source'] = options.source;
    }
    
    // Search in message
    if (options.search) {
      query['message'] = { $regex: options.search, $options: 'i' };
    }
    
    // Query MongoDB
    const logs = await db
      .collection('error_logs')
      .find(query)
      .sort({ timestamp: -1 })
      .limit(options.limit)
      .toArray();
    
    // Output logs
    if (options.json) {
      console.log(JSON.stringify(logs, null, 2));
    } else {
      console.log(`Found ${logs.length} logs:`);
      logs.forEach((log, index) => {
        console.log(`\n--- Log #${index + 1} ---`);
        console.log(`Time: ${new Date(log.timestamp).toLocaleString()}`);
        console.log(`Level: ${log.level}`);
        console.log(`Error: ${log.name}: ${log.message}`);
        
        if (log.stack) {
          console.log('\nStack:');
          console.log(log.stack);
        }
        
        console.log('\nMetadata:');
        console.log(JSON.stringify(log.metadata || {}, null, 2));
      });
    }
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
}

// View logs from the file system
async function viewFileSystemLogs(options) {
  const logDir = path.join(__dirname, '../logs');
  const errorLogFile = path.join(logDir, 'error.log');
  
  if (!fs.existsSync(errorLogFile)) {
    console.log('No error logs found.');
    return;
  }
  
  console.log(`Reading logs from ${errorLogFile}...`);
  
  // Calculate cutoff date
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - options.days);
  
  // Read and parse logs
  const logs = [];
  let currentLog = null;
  let lineCount = 0;
  
  const fileStream = fs.createReadStream(errorLogFile);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });
  
  for await (const line of rl) {
    lineCount++;
    
    // Check if this is the start of a new log entry
    if (line.match(/^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\]/)) {
      // Save previous log if it exists
      if (currentLog) {
        logs.push(currentLog);
        
        // Check if we've reached the limit
        if (logs.length >= options.limit) {
          logs.shift(); // Remove oldest log when we hit the limit
        }
      }
      
      // Extract timestamp and level
      const timestampMatch = line.match(/^\[([^\]]+)\]/);
      const levelMatch = line.match(/^\[[^\]]+\] \[([^\]]+)\]/);
      
      const timestamp = timestampMatch ? timestampMatch[1] : '';
      const level = levelMatch ? levelMatch[1] : '';
      
      // Extract error message
      const messagePart = line.replace(/^\[[^\]]+\] \[[^\]]+\] /, '');
      
      // Create new log entry
      currentLog = {
        timestamp: new Date(timestamp),
        level,
        message: messagePart,
        stack: '',
        metadata: {},
        lines: [line]
      };
      
    } else if (currentLog) {
      // Append to current log
      currentLog.lines.push(line);
      
      // Try to parse stack trace
      if (line.startsWith('Stack:')) {
        currentLog.stack = line.substring(7);
      } else if (line.startsWith('Context:')) {
        try {
          currentLog.metadata = JSON.parse(line.substring(9));
        } catch (e) {
          // Ignore JSON parse errors
        }
      }
    }
  }
  
  // Add the last log if it exists
  if (currentLog) {
    logs.push(currentLog);
  }
  
  // Filter logs
  const filteredLogs = logs.filter(log => {
    // Filter by date
    if (options.days && log.timestamp < cutoffDate) {
      return false;
    }
    
    // Filter by level
    if (options.level && log.level.toLowerCase() !== options.level.toLowerCase()) {
      return false;
    }
    
    // Filter by source
    if (options.source && !(log.metadata.source === options.source)) {
      return false;
    }
    
    // Search in message
    if (options.search && !log.message.toLowerCase().includes(options.search.toLowerCase())) {
      return false;
    }
    
    return true;
  });
  
  // Output logs
  if (options.json) {
    console.log(JSON.stringify(filteredLogs, null, 2));
  } else {
    console.log(`Found ${filteredLogs.length} logs out of ${logs.length} total entries:`);
    
    // Sort logs by timestamp (newest first)
    filteredLogs.sort((a, b) => b.timestamp - a.timestamp);
    
    // Limit output
    const displayLogs = filteredLogs.slice(0, options.limit);
    
    displayLogs.forEach((log, index) => {
      console.log(`\n--- Log #${index + 1} ---`);
      console.log(`Time: ${log.timestamp.toLocaleString()}`);
      console.log(`Level: ${log.level}`);
      console.log(`Message: ${log.message}`);
      
      if (log.stack) {
        console.log('\nStack:');
        console.log(log.stack);
      }
      
      console.log('\nMetadata:');
      console.log(JSON.stringify(log.metadata, null, 2));
    });
  }
}

// Helper function to get argument value
function getArgValue(args, name) {
  const arg = args.find(a => a.startsWith(`${name}=`));
  return arg ? arg.split('=')[1] : null;
}

// Run the script
main().catch(console.error); 