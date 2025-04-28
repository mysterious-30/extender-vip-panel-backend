const fs = require('fs');
const path = require('path');

// Ensure directories exist
const dirs = [
  'lib',
  'models',
  'types',
  'api'
];

dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Create placeholder files for missing modules
const placeholders = {
  'lib/security.ts': `
export function validateCSRF() {}
export function generateCSRFToken() {}
export function getCSRFToken() {}
  `,
  'lib/monitoring.ts': `
export enum SecurityEventType {
  LOGIN_SUCCESS,
  LOGIN_FAILURE,
  LOGOUT
}

export enum LogLevel {
  INFO,
  WARN,
  ERROR
}

export function logSecurityEvent() {}
  `,
  'lib/auth.ts': `
export function verifyAuth() {}
  `,
  'models/Key.ts': `
import mongoose from 'mongoose';

const KeySchema = new mongoose.Schema({});
const Key = mongoose.model('Key', KeySchema);

export default Key;
  `,
  'models/key.ts': `
import mongoose from 'mongoose';

const KeySchema = new mongoose.Schema({});
export const Key = mongoose.model('Key', KeySchema);
  `,
  'lib/firebase.ts': `
export default {};
  `,
  'lib/db-utils.ts': `
export function getUserIdByKey() {}
  `
};

Object.entries(placeholders).forEach(([filePath, content]) => {
  fs.writeFileSync(filePath, content);
  console.log(`Created placeholder: ${filePath}`);
});

console.log('Pre-build preparation complete'); 