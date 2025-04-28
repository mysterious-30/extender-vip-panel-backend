const requiredEnvVars = {
  NODE_ENV: process.env.NODE_ENV || 'production',
  PORT: parseInt(process.env.PORT || '3001', 10),
  HOST: process.env.HOST || '0.0.0.0',
  JWT_SECRET: process.env.JWT_SECRET,
  MONGO_URL: process.env.MONGO_URL,
  FRONTEND_URL: process.env.FRONTEND_URL || 'https://your-frontend-domain.vercel.app',
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  COMPRESSION_LEVEL: parseInt(process.env.COMPRESSION_LEVEL || '6', 10)
};

function validateEnv() {
  const missingVars = [];
  
  // Check for required variables
  if (!requiredEnvVars.JWT_SECRET) {
    missingVars.push('JWT_SECRET');
  }
  
  if (!requiredEnvVars.MONGO_URL) {
    missingVars.push('MONGO_URL');
  }
  
  // Validate numeric values
  if (isNaN(requiredEnvVars.PORT) || requiredEnvVars.PORT <= 0) {
    missingVars.push('PORT (must be a positive number)');
  }
  
  if (isNaN(requiredEnvVars.RATE_LIMIT_WINDOW_MS) || requiredEnvVars.RATE_LIMIT_WINDOW_MS <= 0) {
    missingVars.push('RATE_LIMIT_WINDOW_MS (must be a positive number)');
  }
  
  if (isNaN(requiredEnvVars.RATE_LIMIT_MAX_REQUESTS) || requiredEnvVars.RATE_LIMIT_MAX_REQUESTS <= 0) {
    missingVars.push('RATE_LIMIT_MAX_REQUESTS (must be a positive number)');
  }
  
  if (isNaN(requiredEnvVars.COMPRESSION_LEVEL) || requiredEnvVars.COMPRESSION_LEVEL < 0 || requiredEnvVars.COMPRESSION_LEVEL > 9) {
    missingVars.push('COMPRESSION_LEVEL (must be between 0 and 9)');
  }
  
  // Validate URLs
  try {
    new URL(requiredEnvVars.FRONTEND_URL);
  } catch (error) {
    missingVars.push('FRONTEND_URL (must be a valid URL)');
  }
  
  if (missingVars.length > 0) {
    throw new Error(`Missing or invalid environment variables: ${missingVars.join(', ')}`);
  }
  
  return requiredEnvVars;
}

module.exports = {
  config: requiredEnvVars,
  validateEnv
}; 