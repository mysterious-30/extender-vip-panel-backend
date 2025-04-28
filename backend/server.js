// Simple Express server for the backend
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// Import database module
const { connectToDatabase, ensureDbConnected, userDB, keysDB, apiTokensDB, bulkKeysDB, referralsDB } = require('./database');

// Import error logger
const { errorLoggerMiddleware, requestLoggerMiddleware, logError, logAppEvent, LogLevel } = require('./lib/error-logger');

// Import API routes
const clientErrorRoutes = require('./api/client-error');

// Import new API routes with error handling
let performanceRoutes;
let userInteractionRoutes;

try {
  performanceRoutes = require('./api/performance');
} catch (err) {
  console.error('Failed to load performance routes:', err.message);
  // Create a dummy router that returns 501 Not Implemented
  const express = require('express');
  performanceRoutes = express.Router();
  performanceRoutes.post('/performance', (req, res) => {
    res.status(501).json({ error: 'Performance logging not available' });
  });
}

try {
  userInteractionRoutes = require('./api/user-interaction');
} catch (err) {
  console.error('Failed to load user interaction routes:', err.message);
  // Create a dummy router that returns 501 Not Implemented
  const express = require('express');
  userInteractionRoutes = express.Router();
  userInteractionRoutes.post('/user-interaction', (req, res) => {
    res.status(501).json({ error: 'User interaction logging not available' });
  });
}

// Add error handling for our system monitor initialization
let monitorRequestMiddleware = (req, res, next) => next(); // Default no-op middleware
let initSystemMonitor = async () => {}; // Default no-op initializer

try {
  // Try to import the system monitor
  const systemMonitor = require('./lib/system-monitor');
  monitorRequestMiddleware = systemMonitor.monitorRequestMiddleware;
  initSystemMonitor = systemMonitor.initSystemMonitor;
} catch (err) {
  console.error('Failed to import system monitor module:', err.message);
  console.log('System monitoring will not be available');
}

// Environment variables
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGO_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

// Create Express app
const app = express();

// Production CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://your-frontend-domain.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control']
}));

// Security middleware
app.use(helmet());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Request ID middleware
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Parse JSON request bodies
app.use(express.json());

// Parse URL-encoded request bodies (needed for Android app)
app.use(express.urlencoded({ extended: true }));

// Parse cookies
app.use(cookieParser());

// Add request and error logging middleware
app.use(requestLoggerMiddleware);

// Add the system monitor middleware after the request logger middleware
app.use(monitorRequestMiddleware);

// Log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Test endpoint to verify server is running
app.get('/api/health', async (req, res) => {
  try {
    const healthStatus = await getHealthStatus();
    res.json(healthStatus);
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to get health status',
      error: error.message
    });
  }
});

// Register API routes
app.use('/api', clientErrorRoutes);
app.use('/api', performanceRoutes);
app.use('/api', userInteractionRoutes);

// Login endpoint to get auth token cookie
app.post('/api/auth/login', async (req, res) => {
  try {
    const { userId, password, referralCode } = req.body;
    
    console.log(`Login attempt for user: ${userId}, referral code provided: ${referralCode ? 'yes' : 'no'}`);
    
    if (!userId || !password) {
      console.log('Login failed: Missing userId or password');
      return res.status(400)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'User ID and password are required'
        });
    }
    
    // Get user from database by credentials
    let user = await userDB.getUserByCredentials(userId, password);
    console.log(`User found in database: ${user ? 'yes' : 'no'}`);
    
    // If user doesn't exist and referral code is provided, try to register a new admin
    if (!user && referralCode) {
      try {
        console.log(`Attempting to create new admin using referral code: ${referralCode}`);
        user = await createAdminFromReferral(userId, password, referralCode);
        console.log(`Admin creation result: ${user ? 'success' : 'failed'}`);
      } catch (err) {
        console.error('Admin creation error:', err);
      }
    }
    
    if (!user) {
      console.log('Login failed: Invalid credentials');
      return res.status(401)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Invalid credentials'
        });
    }
    
    // Check if admin account is inactive
    if (user.role === 'admin' && user.isActive === false) {
      console.log(`Login blocked: Admin account ${userId} is inactive`);
      return res.status(403)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Your account has been deactivated. Please contact the owner for assistance.',
          user: {
            userId: user.userId,
            name: user.name,
            role: user.role,
            isActive: false
          }
        });
    }
    
    // Check if admin account is expired
    if (user.role === 'admin' && user.expiryDate) {
      const expiryDate = new Date(user.expiryDate);
      const now = new Date();
      
      if (expiryDate < now) {
        console.log(`Login blocked: Admin account ${userId} is expired (expiry: ${user.expiryDate})`);
        
        // Update isActive status to false for expired accounts
        try {
          await userDB.updateAdminStatus(user._id || user.id, false);
          console.log(`Updated admin status to inactive due to expiry: ${userId}`);
        } catch (updateErr) {
          console.error('Error updating admin active status on expiry:', updateErr);
        }
        
        return res.status(403)
          .header('Content-Type', 'application/json')
          .json({
            success: false,
            message: 'Your account has expired. Please contact the owner to renew your subscription.',
            user: {
              userId: user.userId,
              name: user.name,
              role: user.role,
              expiryDate: user.expiryDate,
              isActive: false
            }
          });
      }
    }
    
    // Generate JWT token
    const token = jwt.sign({
      id: user._id || user.id,
      userId: user.userId,
      role: user.role,
      name: user.name
    }, JWT_SECRET, { expiresIn: '24h' });
    
    // Set auth cookie
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // Return user data without password
    const userResponse = {
      id: user.id,
      userId: user.userId,
      name: user.name,
      role: user.role,
      balance: user.balance,
      expiryDate: user.expiryDate
    };
    
    console.log('Login successful, returning user data');
    
    // Prepare response
    const responseData = {
      success: true,
      user: userResponse
    };
    
    // Log response for debugging
    console.log('Auth response:', JSON.stringify(responseData));
    
    // Send response with explicit content type
    return res.status(200)
      .header('Content-Type', 'application/json')
      .json(responseData);
    
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500)
      .header('Content-Type', 'application/json')
      .json({
        success: false,
        message: 'Server error during login'
      });
  }
});

// Helper function to get user from auth token
async function getUserFromToken(authToken) {
  if (!authToken) return null;

  try {
    // Verify and decode JWT token
    const decoded = jwt.verify(authToken, JWT_SECRET);
    
    // Get user from database by ID
    const userId = decoded.id || decoded.userId;
    let user = null;
    
    if (userId) {
      // Try multiple methods to find the user
      if (ObjectId.isValid(userId)) {
        // Try to find by MongoDB _id first
        user = await userDB.getUserById(userId);
      }
      
      // If not found, try by userId field
      if (!user) {
        user = await userDB.getUserByUserId(userId);
      }
      
      // If still not found, try a direct query by userId
      if (!user) {
        const { db } = await connectToDatabase();
        user = await db.collection('users').findOne({ userId: userId });
      }
      
      // If still not found and id is an email, try by email
      if (!user && userId.includes('@')) {
        const { db } = await connectToDatabase();
        user = await db.collection('users').findOne({ email: userId });
      }
    }
    
    // Log user info or error for debugging
    if (user) {
      console.log(`Found user: ${user.userId || user.id} with role: ${user.role}`);
    } else {
      console.log(`User not found for ID: ${userId}`);
    }
    
    // Validate that user exists and role matches
    if (user && user.role === decoded.role) {
      // Ensure user object has consistent id field
      if (!user.id && user._id) {
        user.id = user._id.toString();
      }
      return user;
    }
    
    return null;
  } catch (error) {
    console.error('Error verifying token:', error);
    return null;
  }
}

// Session check endpoint
app.get('/api/auth/check-session', async (req, res) => {
  try {
    console.log('[Session Check] Request received');
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      console.log('[Session Check] No authentication token found');
      return res.status(401).json({
        success: false,
        message: 'No authentication token found'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    
    if (!user) {
      console.log('[Session Check] Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    console.log('[Session Check] User found:', {
      id: user.id,
      userId: user.userId,
      role: user.role,
      name: user.name,
      balance: user.balance,
      expiryDate: user.expiryDate
    });
    
    // Check if user account is expired (if applicable)
    if (user.expiryDate && new Date(user.expiryDate) < new Date()) {
      console.log('[Session Check] User account has expired');
      
      // If it's an admin account, update the isActive status
      if (user.role === 'admin') {
        try {
          await userDB.updateAdminStatus(user._id || user.id, false);
          console.log(`[Session Check] Updated admin status to inactive due to expiry: ${user.userId}`);
        } catch (updateErr) {
          console.error('[Session Check] Error updating admin active status on expiry:', updateErr);
        }
      }
      
      return res.status(403).json({
        success: false,
        message: 'User account has expired'
      });
    }
    
    // Return user data without password
    const userResponse = {
      id: user.id,
      userId: user.userId,
      name: user.name || user.userId, // Fallback to userId if name is not set
      role: user.role,
      balance: user.balance || 0, // Default to 0 if balance is not set
      expiryDate: user.expiryDate
    };
    
    console.log('[Session Check] Returning user data:', userResponse);
    
    return res.json({
      success: true,
      user: userResponse
    });
  } catch (error) {
    console.error('Session check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during session check'
    });
  }
});

// Change password endpoint
app.post('/api/auth/change-password', async (req, res) => {
  try {
    console.log('[Change Password] Request received');
    const { currentPassword, newPassword } = req.body;
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      console.log('[Change Password] No authentication token found');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    
    if (!user) {
      console.log('[Change Password] Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    console.log(`[Change Password] Attempting to change password for user: ${user.userId}`);
    
    // Validate input
    if (!currentPassword || !newPassword) {
      console.log('[Change Password] Missing current or new password');
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }
    
    // Validate current password
    let isPasswordValid = false;
    
    if (user.password && user.password.startsWith('$2')) {
      // Password is bcrypt hashed
      isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    } else {
      // Password is stored as plaintext (legacy)
      isPasswordValid = user.password === currentPassword;
    }
    
    if (!isPasswordValid) {
      console.log('[Change Password] Current password is incorrect');
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
    
    // Update the password in the database
    try {
      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);
      
      // Update user's password
      await userDB.updateUserPassword(user._id || user.id, hashedPassword);
      console.log(`[Change Password] Password updated successfully for user: ${user.userId}`);
      
      return res.json({
        success: true,
        message: 'Password changed successfully'
      });
    } catch (updateErr) {
      console.error('[Change Password] Error updating password:', updateErr);
      return res.status(500).json({
        success: false,
        message: 'Failed to update password'
      });
    }
  } catch (error) {
    console.error('Change password error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during password change'
    });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  try {
    res.clearCookie('auth_token', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/'
    });
    
    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
});

// Dashboard stats endpoint
app.get('/api/dashboard/stats', async (req, res) => {
  try {
    // Check auth token
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Different stats for different roles
    let stats = {};
    
    // For Owner role - provide full system stats
    if (user.role === 'owner') {
      // Get real-time statistics from database
      const allUsers = await userDB.getAllUsers();
      
      // Count total users (only real users with valid roles, excluding the 'user' account)
      const totalUsers = allUsers.filter(user => 
        user.userId !== 'system' && 
        user.userId !== 'user' &&
        ['owner', 'admin', 'user'].includes(user.role)
      ).length;
      
      // Count admin users
      const totalAdmins = allUsers.filter(user => user.role === 'admin').length;
      
      // Get all keys from database
      const allKeys = await keysDB.getAllKeys();
      const totalKeys = allKeys.length;
      
      // Calculate total balance across all users
      const totalBalance = allUsers.reduce((total, user) => {
        return total + (user.balance || 0);
      }, 0);
      
      // Count active subscriptions (users with non-expired expiryDate)
      const now = new Date();
      const activeSubscriptions = allUsers.filter(user => 
        user.expiryDate && new Date(user.expiryDate) > now
      ).length;
      
      stats = {
        totalUsers,
        totalAdmins,
        totalKeys,
        totalBalance,
        activeSubscriptions,
        monthlyRevenue: '$3,750', // This could be calculated from actual payment records
        systemHealth: '98%',
        pendingApprovals: 7  // This could come from an approvals collection
      };
    } 
    // For Admin role - provide only their own key stats
    else if (user.role === 'admin') {
      // Get keys generated by this admin
      const adminKeys = await keysDB.getKeysByUser(user.id);
      
      // Count total keys for this admin
      const totalKeys = adminKeys.length;
      
      // Count active keys (not expired) for this admin
      const now = new Date();
      const activeKeys = adminKeys.filter(key => 
        key.status === 'active' && new Date(key.expiresAt) > now
      ).length;
      
      stats = {
        totalKeys,
        activeKeys
      };
    }
    
    return res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching dashboard stats'
    });
  }
});

// Reset owner balance endpoint
app.post('/api/owner/reset-balance', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can access this endpoint
    if (user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only owner can reset their balance'
      });
    }
    
    // Reset owner's balance to Infinity
    console.log('Resetting owner balance to Infinity for user:', user);
    
    try {
      // Ensure database is connected
      await ensureDbConnected();
      
      // Use the updateAdminBalance function from userDB
      // This is designed to update a user's balance
      const result = await userDB.updateAdminBalance(user, Infinity);
      
      console.log('Reset balance result:', result);
      
      return res.status(200).json({
        success: true,
        message: 'Owner balance reset to unlimited'
      });
    } catch (dbError) {
      console.error('Error in database operation:', dbError);
      return res.status(500).json({
        success: false,
        message: 'Failed to reset owner balance: ' + dbError.message
      });
    }
  } catch (error) {
    console.error('Error resetting owner balance:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while resetting owner balance'
    });
  }
});

// Get API tokens endpoint
app.get('/api/api-tokens', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const page = parseInt(req.query.page) || 1;
    const perPage = 10;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only admin or owner can access API tokens
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only admins or owners can access API tokens'
      });
    }
    
    // Get tokens from database based on user role
    let tokens = [];
    if (user.role === 'owner') {
      // Owner can see all tokens
      tokens = await apiTokensDB.getAllTokens();
    } else {
      // Admin can only see their own tokens
      tokens = await apiTokensDB.getTokensByUser(user.id);
    }
    
    // Calculate pagination
    const totalTokens = tokens.length;
    const totalPages = Math.ceil(totalTokens / perPage);
    const startIdx = (page - 1) * perPage;
    const paginatedTokens = tokens.slice(startIdx, startIdx + perPage);
    
    return res.status(200).json({
      success: true,
      tokens: paginatedTokens,
      pagination: {
        page,
        perPage,
        totalTokens,
        totalPages
      }
    });
  } catch (error) {
    console.error('Error getting API tokens:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while getting API tokens'
    });
  }
});

// Create API token endpoint
app.post('/api/api-tokens', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only admin or owner can create API tokens
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only admins or owners can create API tokens'
      });
    }
    
    const { name } = req.body;
    
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Token name is required'
      });
    }
    
    // Generate a unique token
    const generateUniqueToken = () => `tk_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
    const token = generateUniqueToken();
    const tokenId = Math.random().toString(36).substring(2, 15);
    
    // Create token object
    const tokenData = {
      id: tokenId,
      name: name.trim(),
      token: token,
      tokenPreview: token.substring(0, 10) + '...',
      userId: user.id,
      createdBy: user.name,
      createdAt: new Date().toISOString(),
      lastUsed: null,
      expiryDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      isActive: true
    };
    
    // Save token to database
    await apiTokensDB.createToken(tokenData);
    
    // Return the created token
    return res.status(201).json({
      success: true,
      message: 'API token created successfully',
      token: token,
      tokenDetails: {
        id: tokenId,
        name: name.trim(),
        token: token.substring(0, 10) + '...',
        createdAt: tokenData.createdAt,
        lastUsed: null,
        expiryDate: tokenData.expiryDate,
        isActive: true
      }
    });
  } catch (error) {
    console.error('Error creating API token:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while creating API token'
    });
  }
});

// Revoke API token endpoint
app.delete('/api/api-tokens/:tokenId', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { tokenId } = req.params;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only admin or owner can revoke API tokens
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only admins or owners can revoke API tokens'
      });
    }
    
    if (!tokenId) {
      return res.status(400).json({
        success: false,
        message: 'Token ID is required'
      });
    }
    
    // Get token from database
    const token = await apiTokensDB.getTokenById(tokenId);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        message: 'Token not found'
      });
    }
    
    // Check if user has permission to revoke the token
    if (user.role !== 'owner' && token.userId !== user.id) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to revoke this token'
      });
    }
    
    // Delete token from database
    await apiTokensDB.deleteToken(tokenId);
    
    return res.status(200).json({
      success: true,
      message: 'API token revoked successfully'
    });
  } catch (error) {
    console.error('Error revoking API token:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while revoking API token'
    });
  }
});

// Admins endpoint (for owner)
app.get('/api/admins', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const page = parseInt(req.query.page) || 1;
    const perPage = 10;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can access admin list
    if (user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Access denied: Owner privileges required'
      });
    }
    
    // Get admins from database (role = 'admin')
    const admins = await userDB.getAllUsers();
    const adminsList = admins.filter(admin => admin.role === 'admin');
    
    // Paginate results
    const totalPages = Math.ceil(adminsList.length / perPage);
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedAdmins = adminsList.slice(startIndex, endIndex);
    
    return res.status(200).json({
      success: true,
      admins: paginatedAdmins,
      totalPages: totalPages,
      currentPage: page
    });
  } catch (error) {
    console.error('Admins listing error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching admins'
    });
  }
});

// Users endpoint (for owner/admin)
app.get('/api/users', (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Only admin or owner can access user list
    if (authToken !== 'admin-jwt-token' && authToken !== 'owner-jwt-token') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden'
      });
    }
    
    // Mock users data
    return res.status(200).json({
      success: true,
      users: Array.from({ length: 10 }, (_, i) => ({
        id: (i + 1).toString(),
        userId: `user${i + 1}`,
        name: `User ${i + 1}`,
        email: `user${i + 1}@example.com`,
        role: i === 0 ? 'admin' : 'user',
        balance: Math.floor(Math.random() * 1000),
        createdAt: new Date(Date.now() - Math.floor(Math.random() * 90) * 24 * 60 * 60 * 1000).toISOString(),
        expiryDate: new Date(Date.now() + Math.floor(Math.random() * 90) * 24 * 60 * 60 * 1000).toISOString(),
        isActive: Math.random() > 0.2
      })),
      totalPages: 5,
      currentPage: 1
    });
  } catch (error) {
    console.error('Users listing error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching users'
    });
  }
});

// Keys endpoint
app.get('/api/keys', async (req, res) => {
  try {
    // Extract query parameters for pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    // Calculate the number of keys to skip
    const skip = (page - 1) * limit;
    
    // Get the user from the session
    const user = await getUserFromSession(req);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    console.log(`Fetching keys for user: ${user.email}, page: ${page}, limit: ${limit}`);
    
    // Retrieve the keys from the database
    let keys = [];
    
    if (user.role === 'owner') {
      // Only owners can see all keys
      console.log('Fetching all keys for owner');
      keys = await keysDB.getAllKeys();
    } else if (user.role === 'admin') {
      // Admins can only see keys they generated
      console.log(`Fetching keys generated by admin ${user.id}`);
      keys = await keysDB.getKeysByUser(user.id);
    } else {
      // Regular users can only see their own keys
      console.log(`Fetching keys for user ${user.id}`);
      keys = await keysDB.getKeysByUser(user.id);
    }
    
    // Calculate pagination details
    const totalKeys = keys.length;
    const totalPages = Math.ceil(totalKeys / limit);
    
    // Apply pagination
    keys = keys.slice(skip, skip + limit);
    
    // Ensure the keys have usageCount based on deviceIds
    keys = keys.map(key => {
      // If deviceIds exists, calculate usageCount from it
      if (key.deviceIds && Array.isArray(key.deviceIds)) {
        key.usageCount = key.deviceIds.length;
      } else if (key.usageCount === undefined) {
        // If usageCount doesn't exist, default to 0
        key.usageCount = 0;
      }
      
      // Add deviceIds array if it doesn't exist to prevent future errors
      if (!key.deviceIds) {
        key.deviceIds = [];
      }
      
      return key;
    });
    
    // Return the keys along with pagination information
    return res.json({
      keys,
      totalKeys,
      totalPages,
      currentPage: page
    });
  } catch (error) {
    console.error('Error fetching keys:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Bulk keys endpoint
app.get('/api/bulk-keys', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner and admins can view bulk keys
    if (user.role !== 'owner' && user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only owners and admins can access bulk keys'
      });
    }
    
    // Get query parameters
    const { searchParams } = new URL(`http://localhost${req.url}`);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    
    // Get bulk keys from database
    let bulkKeys;
    if (user.role === 'owner') {
      // Owner can see all bulk keys
      console.log('Fetching all bulk keys (owner access)');
      bulkKeys = await bulkKeysDB.getAllBulkKeys();
    } else {
      // Admins can only see their own bulk keys
      console.log(`Fetching bulk keys for admin ${user.id}`);
      bulkKeys = await bulkKeysDB.getBulkKeysByUser(user.id);
    }
    
    console.log(`Retrieved ${bulkKeys.length} bulk key folders`);
    
    // Ensure consistent field names for frontend compatibility
    const normalizedBulkKeys = bulkKeys.map(folder => {
      // Create a consistent object with both id/folderId and name/folderName
      return {
        ...folder,
        id: folder.id || folder._id,
        folderId: folder.folderId || folder.id || folder._id,
        name: folder.name || folder.folderName,
        folderName: folder.folderName || folder.name
      };
    });
    
    if (normalizedBulkKeys.length > 0) {
      console.log('First folder details after normalization:', {
        id: normalizedBulkKeys[0].id,
        folderId: normalizedBulkKeys[0].folderId,
        name: normalizedBulkKeys[0].name,
        folderName: normalizedBulkKeys[0].folderName,
        createdAt: normalizedBulkKeys[0].createdAt
      });
    }
    
    // Paginate results
    const totalPages = Math.ceil(normalizedBulkKeys.length / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedBulkKeys = normalizedBulkKeys.slice(startIndex, endIndex);
    
    console.log(`Returning page ${page} of ${totalPages} (${paginatedBulkKeys.length} folders)`);
    
    return res.status(200).json({
      success: true,
      bulkKeys: paginatedBulkKeys,
      totalPages: totalPages,
      currentPage: page
    });
  } catch (error) {
    console.error('Bulk keys listing error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching bulk keys'
    });
  }
});

// Generate key endpoint
app.post('/api/keys', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Parse request body
    const { app, duration, devices, totalCost, price, customKey } = req.body;
    
    if (!app || !duration) {
      return res.status(400).json({
        success: false,
        message: 'App name and duration are required'
      });
    }
    
    // Validate the custom key length if provided
    if (customKey) {
      if (customKey.length < 6 || customKey.length > 12) {
        return res.status(400).json({
          success: false,
          message: 'Custom key must be between 6 and 12 characters'
        });
      }
      
      // Ensure the key contains only alphanumeric characters
      if (!/^[a-zA-Z0-9]+$/.test(customKey)) {
        return res.status(400).json({
          success: false,
          message: 'Custom key must contain only letters and numbers'
        });
      }
    }

    // Generate key for pricing
    const finalCost = price ? price * (devices || 1) : 60 * (devices || 1);
    console.log(`Using finalCost: ${finalCost} for key generation (${price} * ${devices || 1})`);
    
    // For admin users, check if they have sufficient balance
    if (user.role === 'admin' && user.balance < finalCost) {
      return res.status(403).json({
        success: false,
        message: `Insufficient balance. Required: ₹${finalCost}, Available: ₹${user.balance || 0}`
      });
    }
    
    // Convert duration to days for expiry calculation
    let expiryDays = 90; // default
    
    if (duration === '2hour') {
      expiryDays = 1/12; // 2 hours as fraction of a day
    } else if (duration === '1day') {
      expiryDays = 1;
    } else if (duration === '3day') {
      expiryDays = 3;
    } else if (duration === '7day') {
      expiryDays = 7;
    } else if (duration === '10day') {
      expiryDays = 10;
    } else if (duration === '30day') {
      expiryDays = 30;
    } else if (duration === '60day') {
      expiryDays = 60;
    }
    
    // Generate a unique key
    const generateUniqueKey = () => {
      // Generate a random value and convert to base36 (alphanumeric)
      // Ensure the key length is between 6 and 12 characters
      const randomPart = Math.random().toString(36).substring(2, 11).toUpperCase();
      // Ensure total length is at least 6 and at most 12 characters
      if (randomPart.length < 6) {
        return `KEY${randomPart.padEnd(6, '0')}`;
      }
      return `KEY${randomPart.substring(0, 9)}`;
    };
    
    // Create new key
    const keyData = {
      id: Math.random().toString(36).substring(2, 15),
      key: customKey || generateUniqueKey(),
      keyName: customKey || "",
      app,
      duration: duration,
      generatedBy: user.role,
      userId: user.id,
      createdBy: user.id, // Add createdBy field to match what my-keys route looks for
      generatedByName: user.name,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString(),
      status: 'active',
      totalCost: finalCost,
      maxDevices: devices || 5,
      usageCount: 0
    };
    
    // Update user balance - skip for owner accounts
    if (user.role !== 'owner') {
      await userDB.updateUserBalance(user.id, finalCost);
    }
    
    // Save key to database
    await keysDB.createKey(keyData);
    
    return res.status(201).json({
      success: true,
      message: 'Key generated successfully',
      key: keyData.key,
      keyData: keyData
    });
  } catch (error) {
    console.error('Error generating key:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while generating key'
    });
  }
});

// Generate bulk keys endpoint
app.post('/api/bulk-keys', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    console.log('Bulk keys generation request received');
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    console.log(`User authenticated: ${user.id}, role: ${user.role}`);
    
    // Only owner can generate bulk keys (modified to restrict admins)
    if (user.role !== 'owner') {
      console.log(`User role ${user.role} not authorized for bulk key generation`);
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only owners can generate bulk keys'
      });
    }
    
    const { name, numberOfKeys, duration, devices, app, bulkKeyType, totalCost, price } = req.body;
    console.log('Bulk key request body:', req.body);
    
    if (!name || !numberOfKeys || !app || !duration) {
      console.log('Missing required fields:', { name, numberOfKeys, app, duration });
      return res.status(400).json({
        success: false,
        message: 'Name, number of keys, duration, and app are required'
      });
    }
    
    // Generate a unique folder ID
    const folderId = `BK_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    console.log(`Generated folder ID: ${folderId}`);
    
    // Convert duration to days for expiry calculation
    let expiryDays = 90; // default
    
    if (duration === '2hour') {
      expiryDays = 1/12; // 2 hours as fraction of a day
    } else if (duration === '1day') {
      expiryDays = 1;
    } else if (duration === '3day') {
      expiryDays = 3;
    } else if (duration === '7day') {
      expiryDays = 7;
    } else if (duration === '10day') {
      expiryDays = 10;
    } else if (duration === '30day') {
      expiryDays = 30;
    } else if (duration === '60day') {
      expiryDays = 60;
    }
    
    // Create bulk key folder with correct maxDevices
    const bulkKeyData = {
      id: folderId,
      name: name.trim(),
      folderName: name.trim(),
      folderId: folderId,
      userId: user.id,
      createdAt: new Date().toISOString(),
      createdBy: user.name,
      creatorName: user.name,
      expiryDays: expiryDays,
      duration: duration,
      maxDevices: devices || 1,
      bulkKeyType: bulkKeyType || 'multi_device',
      totalKeys: numberOfKeys,
      activeKeys: numberOfKeys,
      expiredKeys: 0
    };
    
    console.log('Creating bulk key folder with data:', bulkKeyData);
    
    // Save bulk key folder to database
    await bulkKeysDB.createBulkKey(bulkKeyData);
    console.log('Bulk key folder created in database');
    
    // Generate the specified number of keys
    const generateUniqueKey = () => {
      // Generate a random value and convert to base36 (alphanumeric)
      // Ensure the key length is between 6 and 12 characters
      const randomPart = Math.random().toString(36).substring(2, 11).toUpperCase();
      // Ensure total length is at least 6 and at most 12 characters
      if (randomPart.length < 6) {
        return `KEY${randomPart.padEnd(6, '0')}`;
      }
      return `KEY${randomPart.substring(0, 9)}`;
    };
    const keys = [];
    
    // Calculate expiry date based on the selected duration
    const expiryDate = new Date(Date.now() + (expiryDays * 24 * 60 * 60 * 1000)).toISOString();
    
    console.log(`Generating ${numberOfKeys} keys with expiry date: ${expiryDate}`);
    
    // Calculate total cost - use the provided totalCost if available
    const finalCost = totalCost || (price ? price * (devices || 1) * numberOfKeys : 20 * (devices || 1) * numberOfKeys);
    console.log(`Using finalCost: ${finalCost} for bulk key generation`);
    
    // Check if the user has enough balance - skip this check for owner accounts
    if (user.role !== 'owner' && user.balance < finalCost) {
      console.log(`Insufficient balance: required ${finalCost}, available ${user.balance}`);
      return res.status(403).json({
        success: false,
        message: 'Insufficient balance'
      });
    }
    
    for (let i = 0; i < numberOfKeys; i++) {
      // Respect the bulkKeyType for maxDevices (1 for single_device)
      const maxDevices = bulkKeyType === 'single_device' ? 1 : (devices || 5);
      const keyCost = price ? price * maxDevices : 20 * maxDevices;
      
      const keyData = {
        id: Math.random().toString(36).substring(2, 15),
        key: generateUniqueKey(),
        app,
        duration: duration,
        generatedBy: user.role,
        userId: user.id,
        generatedByName: user.name,
        createdAt: new Date().toISOString(),
        expiresAt: expiryDate,
        status: 'active',
        totalCost: keyCost,
        maxDevices: maxDevices,
        usageCount: 0,
        bulkKeyId: folderId,
        bulkKeyType: bulkKeyType || 'multi_device'
      };
      
      // Save key to database
      await keysDB.createKey(keyData);
      keys.push(keyData.key);
    }
    
    // Update user balance with the exact same totalCost that was used in the check - skip for owner accounts
    if (user.role !== 'owner') {
      await userDB.updateUserBalance(user.id, finalCost);
    }
    
    console.log(`Generated ${keys.length} keys successfully, deducted ${finalCost} from balance`);
    
    return res.status(201).json({
      success: true,
      message: `${numberOfKeys} keys generated successfully`,
      folderId,
      folderName: name,
      keys
    });
  } catch (error) {
    console.error('Error generating bulk keys:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while generating bulk keys'
    });
  }
});

// Referrals endpoint
app.get('/api/referrals', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const page = parseInt(req.query.page) || 1;
    const perPage = 10;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can access referrals
    if (user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Owner access required'
      });
    }
    
    // Get referrals from database
    const referrals = await referralsDB.getAllReferrals();
    
    // Paginate results
    const totalPages = Math.ceil(referrals.length / perPage);
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedReferrals = referrals.slice(startIndex, endIndex);
    
    return res.status(200).json({
      success: true,
      referrals: paginatedReferrals,
      totalPages: totalPages,
      currentPage: page
    });
  } catch (error) {
    console.error('Referrals listing error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching referrals'
    });
  }
});

// Generate referral endpoint
app.post('/api/referrals', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can generate referrals
    if (user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Owner access required'
      });
    }
    
    const { discount, maxUses, expiryDays, initialBalance } = req.body;
    
    if (!discount || discount < 1 || discount > 100) {
      return res.status(400).json({
        success: false,
        message: 'Invalid discount (must be between 1 and 100)'
      });
    }
    
    if (!maxUses || maxUses < 1) {
      return res.status(400).json({
        success: false,
        message: 'Invalid max uses (must be at least 1)'
      });
    }
    
    // Generate a unique referral code
    const generateUniqueCode = () => `REF-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    
    // Create referral data
    const referralData = {
      id: Math.random().toString(36).substring(2, 15),
      code: generateUniqueCode(),
      discount: parseInt(discount),
      initialBalance: initialBalance ? parseInt(initialBalance) : 500,
      usageCount: 0,
      maxUses: parseInt(maxUses),
      createdAt: new Date().toISOString(),
      expiryDate: expiryDays ? new Date(Date.now() + parseInt(expiryDays) * 24 * 60 * 60 * 1000).toISOString() : null,
      isActive: true,
      userId: user.id
    };
    
    console.log('Creating referral with data:', referralData);
    
    // Save referral to database
    await referralsDB.createReferral(referralData);
    
    return res.status(201).json({
      success: true,
      message: 'Referral code generated successfully',
      referral: referralData
    });
  } catch (error) {
    console.error('Referral generation error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while generating referral'
    });
  }
});

// Folder keys endpoint
app.get('/api/bulk-keys/folders/:folderId/keys', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { folderId } = req.params;
    
    console.log(`GET /api/bulk-keys/folders/${folderId}/keys - Request received`);
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    console.log(`User authenticated: ${user.id}, role: ${user.role}`);
    
    // Only admin or owner can access folder keys
    if (user.role !== 'admin' && user.role !== 'owner') {
      console.log(`User role ${user.role} not authorized to view folder keys`);
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only admins or owners can access folder keys'
      });
    }
    
    if (!folderId) {
      console.log('No folder ID provided in request');
      return res.status(400).json({
        success: false,
        message: 'Folder ID is required'
      });
    }
    
    console.log(`Looking up folder with ID: ${folderId}`);
    
    // Get folder from database
    const folder = await bulkKeysDB.getBulkKeyById(folderId);
    
    if (!folder) {
      console.log(`Folder with ID ${folderId} not found`);
      return res.status(404).json({
        success: false,
        message: 'Folder not found'
      });
    }
    
    console.log(`Found folder: ${folder.name || folder.folderName}, created by: ${folder.createdBy || folder.creatorName}`);
    
    // Check if user has permission to access the folder
    if (user.role !== 'owner' && folder.userId !== user.id) {
      console.log(`User ${user.id} does not have permission to access folder ${folderId}`);
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to access this folder'
      });
    }
    
    // Normalize folder data
    const normalizedFolder = {
      ...folder,
      id: folder.id || folder._id,
      folderId: folder.folderId || folder.id || folder._id,
      name: folder.name || folder.folderName,
      folderName: folder.folderName || folder.name,
      createdBy: folder.createdBy || folder.creatorName,
      creatorName: folder.creatorName || folder.createdBy
    };
    
    // Get keys for this folder
    console.log(`Fetching keys for folder ${folderId}`);
    const folderKeys = await keysDB.getAllBulkKeys(folderId);
    console.log(`Found ${folderKeys.length} keys for folder ${folderId}`);
    
    // Ensure each key has consistent field names
    const normalizedKeys = folderKeys.map(key => ({
      ...key,
      id: key.id || key._id,
      bulkKeyId: key.bulkKeyId || key.folderId,
      usedDevices: key.usageCount || 0
    }));
    
    return res.status(200).json({
      success: true,
      folder: normalizedFolder,
      keys: normalizedKeys
    });
  } catch (error) {
    console.error('Error fetching folder keys:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching folder keys'
    });
  }
});

// Delete folder endpoint
app.delete('/api/bulk-keys/folders/:folderId', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { folderId } = req.params;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only admin or owner can delete folders
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Only admins or owners can delete folders'
      });
    }
    
    if (!folderId) {
      return res.status(400).json({
        success: false,
        message: 'Folder ID is required'
      });
    }
    
    // Get folder from database
    const folder = await bulkKeysDB.getBulkKeyById(folderId);
    
    if (!folder) {
      return res.status(404).json({
        success: false,
        message: 'Folder not found'
      });
    }
    
    // Check if user has permission to delete the folder
    if (user.role !== 'owner' && folder.userId !== user.id) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to delete this folder'
      });
    }
    
    // Get all keys for this folder
    const allKeys = await keysDB.getAllKeys();
    const folderKeys = allKeys.filter(key => key.bulkKeyId === folderId);
    
    // Delete all keys in the folder
    for (const key of folderKeys) {
      await keysDB.deleteKey(key.id);
    }
    
    // Delete the folder
    await bulkKeysDB.deleteBulkKey(folderId);
    
    return res.status(200).json({
      success: true,
      message: 'Folder and all associated keys deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting folder:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while deleting folder'
    });
  }
});

// Delete key endpoint
app.delete('/api/keys/:keyId', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { keyId } = req.params;
    
    console.log(`DELETE /api/keys/${keyId} - Request received`);
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    console.log(`User authenticated: ${user.id}, role: ${user.role}`);
    
    if (!keyId) {
      console.log('No key ID provided in request');
      return res.status(400).json({
        success: false,
        message: 'Key ID is required'
      });
    }
    
    // Get key from database
    const key = await keysDB.getKeyById(keyId);
    
    if (!key) {
      console.log(`Key with ID ${keyId} not found`);
      // If the key is not found but it has a valid format, we'll try to delete it anyway
      // This helps with cases where the key reference exists but the actual key is difficult to retrieve
      if (ObjectId.isValid(keyId)) {
        console.log(`Key not found, but ID is valid ObjectId format. Attempting deletion anyway.`);
        const deleteResult = await keysDB.deleteKey(keyId);
        
        if (deleteResult.deletedCount > 0) {
          console.log(`Successfully deleted key with ID ${keyId}`);
          return res.status(200).json({
            success: true,
            message: 'Key deleted successfully'
          });
        } else {
          console.log(`Failed to delete key with ID ${keyId}`);
          return res.status(404).json({
            success: false,
            message: 'Key not found or could not be deleted'
          });
        }
      }
      
      return res.status(404).json({
        success: false,
        message: 'Key not found'
      });
    }
    
    console.log(`Found key: ${key.key}, owned by: ${key.userId || 'unknown'}`);
    
    // Check if user has permission to delete the key
    if (user.role !== 'owner' && user.role !== 'admin' && key.userId !== user.id) {
      console.log(`User ${user.id} does not have permission to delete key ${keyId}`);
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to delete this key'
      });
    }
    
    // Delete key from database
    const deleteResult = await keysDB.deleteKey(keyId);
    
    if (deleteResult.deletedCount > 0) {
      console.log(`Successfully deleted key with ID ${keyId}`);
      return res.status(200).json({
        success: true,
        message: 'Key deleted successfully'
      });
    } else {
      console.log(`Failed to delete key with ID ${keyId}`);
      return res.status(500).json({
        success: false,
        message: 'Failed to delete key'
      });
    }
  } catch (error) {
    console.error('Error deleting key:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while deleting key'
    });
  }
});

// Reset key endpoint
app.post('/api/keys/:keyId/reset', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { keyId } = req.params;
    
    if (!authToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    if (!keyId) {
      return res.status(400).json({
        success: false,
        message: 'Key ID is required'
      });
    }
    
    // Get key from database
    const key = await keysDB.getKeyById(keyId);
    
    if (!key) {
      return res.status(404).json({
        success: false,
        message: 'Key not found'
      });
    }
    
    // Check if key has expired
    const currentDate = new Date();
    if (key.expiresAt && new Date(key.expiresAt) < currentDate) {
      return res.status(403).json({
        success: false,
        message: 'Cannot reset an expired key. This key has expired and is no longer valid.'
      });
    }
    
    // Check if user has permission to reset the key
    if (user.role !== 'owner' && user.role !== 'admin' && key.userId !== user.id) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to reset this key'
      });
    }
    
    // Reset the key's device usage
    await keysDB.resetKey(keyId);
    
    return res.status(200).json({
      success: true,
      message: 'Key reset successfully'
    });
  } catch (error) {
    console.error('Error resetting key:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while resetting key'
    });
  }
});

// Admin balance update endpoint
app.put('/api/admins/:adminId/balance', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { adminId } = req.params;
    let { amount } = req.body;
    
    // Convert amount to number if it's a string
    if (typeof amount === 'string') {
      amount = parseFloat(amount);
    }
    
    console.log(`PUT /api/admins/${adminId}/balance - Request received with amount:`, amount, typeof amount);
    console.log(`Request body:`, req.body);
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can update admin balance
    if (user.role !== 'owner') {
      console.log(`User role ${user.role} not authorized to update admin balance`);
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Owner access required'
      });
    }
    
    if (!adminId) {
      console.log('No admin ID provided in request');
      return res.status(400).json({
        success: false,
        message: 'Admin ID is required'
      });
    }
    
    // Validate amount after potential conversion
    if (isNaN(amount) || amount <= 0) {
      console.log(`Invalid amount provided: ${amount}, type: ${typeof amount}`);
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required (must be a positive number)'
      });
    }
    
    console.log(`Looking up admin with ID: ${adminId}`);
    
    // Get admin from database
    const admin = await userDB.getUserById(adminId);
    
    if (!admin) {
      console.log(`Admin with ID ${adminId} not found`);
      return res.status(404).json({
        success: false,
        message: 'Admin not found'
      });
    }
    
    if (admin.role !== 'admin') {
      console.log(`User with ID ${adminId} is not an admin, role: ${admin.role}`);
      return res.status(400).json({
        success: false,
        message: 'User is not an admin'
      });
    }
    
    console.log(`Found admin:`, admin);
    const oldBalance = admin.balance || 0;
    const newBalance = oldBalance + amount;
    console.log(`Updating admin balance for: ${admin.userId}, current balance: ${oldBalance}, adding: ${amount}, new balance: ${newBalance}`);
    
    // Update admin balance using the improved function from database.js
    try {
      // Update the admin document with the new balance (adding to existing balance)
      const updateResult = await userDB.updateAdminBalance(admin, newBalance);
      
      console.log(`Admin balance successfully updated from ${oldBalance} to ${newBalance}`);
      
      return res.status(200).json({
        success: true,
        message: `Admin balance updated successfully, added ₹${amount}`,
        newBalance: newBalance // Return the new balance as a number
      });
    } catch (dbError) {
      console.error('Database error updating admin balance:', dbError);
      return res.status(500).json({
        success: false,
        message: `Database error while updating admin balance: ${dbError.message}`
      });
    }
  } catch (error) {
    console.error('Error updating admin balance:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating admin balance: ' + error.message
    });
  }
});

// Admin expiry update endpoint
// Modified endpoint to allow updating expired admin accounts
app.put('/api/admins/:adminId/expiry', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { adminId } = req.params;
    const { expiryDate } = req.body;
    
    console.log(`PUT /api/admins/${adminId}/expiry - Request received with expiryDate:`, expiryDate);
    console.log(`Request body:`, req.body);
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can update admin expiry
    if (user.role !== 'owner') {
      console.log(`User role ${user.role} not authorized to update admin expiry`);
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Owner access required'
      });
    }
    
    if (!adminId) {
      console.log('No admin ID provided in request');
      return res.status(400).json({
        success: false,
        message: 'Admin ID is required'
      });
    }
    
    if (!expiryDate) {
      console.log('No expiry date provided in request');
      return res.status(400).json({
        success: false,
        message: 'Expiry date is required'
      });
    }

    console.log(`Looking up admin with ID: ${adminId}`);
    
    // Get admin from database
    const admin = await userDB.getUserById(adminId);
    
    if (!admin) {
      console.log(`Admin with ID ${adminId} not found`);
      return res.status(404).json({
        success: false,
        message: 'Admin not found'
      });
    }
    
    if (admin.role !== 'admin') {
      console.log(`User with ID ${adminId} is not an admin, role: ${admin.role}`);
      return res.status(400).json({
        success: false,
        message: 'User is not an admin'
      });
    }
    
    console.log(`Found admin:`, admin);
    const oldExpiryDate = admin.expiryDate || 'Not set';
    console.log(`Updating admin expiry for: ${admin.userId}, current expiry: ${oldExpiryDate}, new expiry: ${expiryDate}`);
    
    // Check if the new expiry date is in the future and update isActive accordingly
    const newExpiryDate = new Date(expiryDate);
    const now = new Date();
    // Remove the expired check since we want to allow updating expired admins
    // const isExpired = newExpiryDate < now;
    
    // Update the admin document with the new expiry date
    await userDB.updateAdminExpiry(admin, expiryDate);
    
    // If expiry date is in the past, set admin to inactive
    // If expiry date is in the future, set admin to active
    // Always set admin to active when expiry date is updated
    const newActiveStatus = true; // Modified to always activate admin on expiry update
    await userDB.updateAdminStatus(adminId, newActiveStatus);
    
    console.log(`Admin expiry updated from ${oldExpiryDate} to ${expiryDate}`);
    console.log(`Admin active status set to ${newActiveStatus ? 'active' : 'inactive'}`);
    
    return res.status(200).json({
      success: true,
      message: `Admin expiry updated to ${new Date(expiryDate).toLocaleDateString()}`,
      expiryDate: expiryDate,
      isActive: newActiveStatus
    });
  } catch (error) {
    console.error('Error updating admin expiry:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating admin expiry: ' + error.message
    });
  }
});

// Update admin active status
app.put('/api/admins/:adminId/status', async (req, res) => {
  try {
    const authToken = req.cookies?.auth_token;
    const { adminId } = req.params;
    const { isActive } = req.body;
    
    console.log(`PUT /api/admins/${adminId}/status - Request received`, { isActive });
    
    if (!authToken) {
      console.log('Authentication token missing');
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid authentication token');
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    // Only owner can update admin status
    if (user.role !== 'owner') {
      console.log(`User role ${user.role} not authorized to update admin status`);
      return res.status(403).json({
        success: false,
        message: 'Forbidden - Owner access required'
      });
    }
    
    if (!adminId) {
      console.log('No admin ID provided in request');
      return res.status(400).json({
        success: false,
        message: 'Admin ID is required'
      });
    }
    
    if (isActive === undefined || isActive === null) {
      console.log('No isActive status provided in request');
      return res.status(400).json({
        success: false,
        message: 'isActive status is required'
      });
    }
    
    console.log(`Looking up admin with ID: ${adminId}`);
    
    // Get admin from database
    const admin = await userDB.getUserById(adminId);
    
    if (!admin) {
      console.log(`Admin with ID ${adminId} not found`);
      return res.status(404).json({
        success: false,
        message: 'Admin not found'
      });
    }
    
    if (admin.role !== 'admin') {
      console.log(`User with ID ${adminId} is not an admin, role: ${admin.role}`);
      return res.status(400).json({
        success: false,
        message: 'User is not an admin'
      });
    }
    
    // If trying to activate an expired account, don't allow it
    if (isActive === true && admin.expiryDate) {
      const expiryDate = new Date(admin.expiryDate);
      const now = new Date();
      
      if (expiryDate < now) {
        console.log(`Cannot activate expired admin account. Admin ${admin.userId} expired on ${admin.expiryDate}`);
        return res.status(400).json({
          success: false,
          message: 'Cannot activate an expired account. Please update the expiry date first.'
        });
      }
    }
    
    console.log(`Updating admin status: ${admin.userId} to ${isActive ? 'active' : 'inactive'}`);
    
    // Convert isActive to boolean to ensure correct type
    const boolIsActive = isActive === true || isActive === 'true';
    
    // Update the admin status
    const updateResult = await userDB.updateAdminStatus(adminId, boolIsActive);
    
    if (!updateResult.success) {
      console.log('Failed to update admin status:', updateResult.message);
      return res.status(500).json({
        success: false,
        message: updateResult.message || 'Failed to update admin status'
      });
    }
    
    console.log(`Admin status successfully updated to ${boolIsActive ? 'active' : 'inactive'}`);
    
    return res.status(200).json({
      success: true,
      message: `Admin is now ${boolIsActive ? 'active' : 'inactive'}`,
      isActive: boolIsActive
    });
  } catch (error) {
    console.error('Error updating admin status:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating admin status: ' + error.message
    });
  }
});

// User registration with referral code
app.post('/api/auth/register', async (req, res) => {
  console.log('Registration request received:', req.body);
  
  try {
    const { userId, password, name, referralCode } = req.body;
    
    // Validate input
    if (!userId || !password || !name || !referralCode) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required: userId, password, name, and referralCode'
      });
    }
    
    // Check if user already exists - additional upfront check before trying to create
    const existingUser = await userDB.getUserById(userId);
    if (existingUser) {
      console.log(`Registration failed: User ID ${userId} already exists`);
      return res.status(400).json({
        success: false,
        message: 'User ID already exists. Please choose a different User ID.'
      });
    }

    // Also check by userId directly since that's what has the unique index
    const existingUserByUserId = await userDB.findUserByUserId(userId);
    if (existingUserByUserId) {
      console.log(`Registration failed: User ID ${userId} already exists (direct check)`);
      return res.status(400).json({
        success: false,
        message: 'User ID already exists. Please choose a different User ID.'
      });
    }
    
    // Verify the referral code
    const referral = await referralsDB.getReferralByCode(referralCode);
    if (!referral) {
      console.log(`Registration failed: Invalid referral code ${referralCode}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid referral code'
      });
    }
    
    if (referral.used) {
      console.log(`Registration failed: Referral code ${referralCode} has already been used`);
      return res.status(400).json({
        success: false,
        message: 'This referral code has already been used'
      });
    }
    
    // Create new admin user (admins are created with referral codes)
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Set expiry date to 30 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 30);

    // Generate a unique ID for the user
    const generateUniqueId = () => `usr_${Math.random().toString(36).substring(2, 15)}`;
    const userId_unique = generateUniqueId();
    
    const newUser = {
      id: userId_unique,  // Unique ID for the user
      userId,
      password: hashedPassword,
      name,
      role: 'admin', // New users from referral are admins
      createdAt: new Date(),
      expiryDate,
      isActive: true,
      balance: referral.initialBalance || 0 // Use initial balance from referral if available
    };
    
    // Create the user
    console.log('Creating new admin user:', { ...newUser, password: '[HIDDEN]' });
    
    try {
      const createResult = await userDB.createUser(newUser);
      
      if (!createResult.success) {
        console.log('Failed to create user:', createResult.message);
        return res.status(500).json({
          success: false,
          message: createResult.message || 'Failed to create user'
        });
      }
      
      // Mark the referral code as used
      await referralsDB.markReferralAsUsed(referralCode, userId);
      
      // Create a session for the new user
      const token = jwt.sign(
        { userId, role: 'admin' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      // Set the cookie
      res.cookie('authToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      console.log(`User ${userId} successfully registered as admin with ID ${userId_unique}`);
      
      // Return success
      return res.status(201).json({
        success: true,
        message: 'Registration successful',
        user: {
          id: userId_unique,
          userId,
          name,
          role: 'admin',
          expiryDate,
          isActive: true,
          balance: newUser.balance
        }
      });
    } catch (error) {
      // Check for duplicate key error
      if (error.name === 'MongoError' || error.name === 'MongoServerError') {
        if (error.code === 11000) {
          console.error('Duplicate key error during registration:', error);
          return res.status(400).json({
            success: false,
            message: 'This User ID is already taken. Please choose a different User ID.'
          });
        }
      }
      throw error; // Rethrow for the outer catch
    }
  } catch (error) {
    console.error('Registration error:', error);
    
    // More specific error handling
    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
      if (error.code === 11000) {
        return res.status(400).json({
          success: false,
          message: 'This User ID is already taken. Please choose a different User ID.'
        });
      }
    }
    
    return res.status(500).json({
      success: false,
      message: 'Server error during registration: ' + error.message
    });
  }
});

// Admin Remove endpoint
app.post('/api/admins/remove', async (req, res) => {
  console.log('Admin removal request received:', req.body);
  
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      console.log('No auth token provided');
      return res.status(401)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Authentication required'
        });
    }
    
    // Get user from auth token
    const user = await getUserFromToken(authToken);
    if (!user) {
      console.log('Invalid auth token');
      return res.status(401)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Invalid authentication token'
        });
    }
    
    console.log('User authenticated:', user.userId, 'with role:', user.role);
    
    // Only owner can remove admins
    if (user.role !== 'owner') {
      console.log('User is not an owner, role:', user.role);
      return res.status(403)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Only owners can remove admins'
        });
    }
    
    // Get admin ID and action from request body
    const { adminId, action } = req.body;
    
    if (!adminId) {
      console.log('No admin ID provided');
      return res.status(400)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Admin ID is required'
        });
    }
    
    if (!action || (action !== 'ban' && action !== 'delete')) {
      console.log('Invalid action:', action);
      return res.status(400)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Action must be either "ban" or "delete"'
        });
    }
    
    console.log(`Attempting to ${action} admin with ID:`, adminId);
    
    // Find the admin
    const admin = await userDB.getUserById(adminId);
    
    if (!admin) {
      console.log('Admin not found with ID:', adminId);
      return res.status(404)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'Admin not found'
        });
    }
    
    if (admin.role !== 'admin') {
      console.log('User with ID', adminId, 'is not an admin. Role:', admin.role);
      return res.status(400)
        .header('Content-Type', 'application/json')
        .json({
          success: false,
          message: 'User is not an admin'
        });
    }
    
    console.log('Found admin:', admin.userId || admin.name);
    
    if (action === 'ban') {
      // Ban the admin by updating the status
      const updateResult = await userDB.updateAdminStatus(adminId, false);
      
      if (!updateResult || !updateResult.success) {
        console.error('Failed to ban admin:', updateResult?.message || 'Unknown error');
        return res.status(500)
          .header('Content-Type', 'application/json')
          .json({
            success: false,
            message: 'Failed to ban admin'
          });
      }
      
      console.log('Admin successfully banned');
      
      return res.status(200)
        .header('Content-Type', 'application/json')
        .json({
          success: true,
          message: 'Admin banned successfully'
        });
    } else {
      // Delete the admin
      try {
        const deleteResult = await userDB.deleteUser(adminId);
        
        // Check if the deletion was successful by checking deletedCount
        if (deleteResult && deleteResult.deletedCount > 0) {
          console.log('Admin successfully deleted, deletedCount:', deleteResult.deletedCount);
          
          return res.status(200)
            .header('Content-Type', 'application/json')
            .json({
              success: true,
              message: 'Admin deleted successfully'
            });
        } else {
          console.error('Failed to delete admin: No documents deleted');
          return res.status(500)
            .header('Content-Type', 'application/json')
            .json({
              success: false,
              message: 'Failed to delete admin: No documents deleted'
            });
        }
      } catch (deleteError) {
        console.error('Error deleting admin:', deleteError);
        return res.status(500)
          .header('Content-Type', 'application/json')
          .json({
            success: false,
            message: `Error deleting admin: ${deleteError.message || 'Unknown error'}`
          });
      }
    }
  } catch (error) {
    console.error('Admin removal error:', error);
    return res.status(500)
      .header('Content-Type', 'application/json')
      .json({
        success: false,
        message: 'Server error during admin removal'
      });
  }
});

// Update the key validation endpoint to implement device tracking
app.post('/api/keys/validate/connect', async (req, res) => {
  try {
    console.log('Android app key validation request received');
    console.log('Request body:', req.body);
    
    // Parse data from form-encoded format
    const user_key = req.body.user_key;
    const serial = req.body.serial; // This is UUID in Android app (device identifier)
    const game = req.body.game;
    
    console.log(`Full request parameters: user_key=${user_key}, serial=${serial}, game=${game}`);
    
    if (!user_key || !serial) {
      console.log('Key validation failed: Missing required parameters');
      return res.status(200).json({
        status: false,
        reason: 'Missing required parameters'
      });
    }
    
    // Ensure database is connected
    await ensureDbConnected();
    
    // Check for the key in both regular keys and bulk keys
    console.log(`Looking for key in database: ${user_key}`);
    
    // Use keysDB functions instead of accessing db directly
    // Get all keys without filtering
    const allKeys = await keysDB.getAllKeys(true); // Include bulk keys
    const keyData = allKeys.find(k => k.key === user_key);
    
    if (!keyData) {
      console.log(`Key validation failed: Key not found in database - ${user_key}`);
      return res.status(200).json({
        status: false,
        reason: 'Invalid key - Key not found in database'
      });
    }
    
    console.log('Key found in database:', keyData);
    
    // Check if key is active
    if (keyData.status !== 'active') {
      console.log(`Key validation failed: Key is not active - ${user_key}, status: ${keyData.status}`);
      return res.status(200).json({
        status: false,
        reason: 'Key is not active'
      });
    }
    
    // Check if key is expired
    const now = new Date();
    const expiryDate = new Date(keyData.expiresAt);
    
    if (expiryDate < now) {
      console.log(`Key validation failed: Key expired - ${user_key}, expiry: ${keyData.expiresAt}`);
      return res.status(200).json({
        status: false,
        reason: 'Key has expired'
      });
    }
    
    // Check if this is a bulk key
    if (keyData.bulkKeyId) {
      console.log(`This is a bulk key with ID: ${keyData.bulkKeyId}`);
      
      try {
        // Get all bulk keys from database
        const allBulkKeys = await bulkKeysDB.getAllBulkKeys();
        console.log(`Found ${allBulkKeys.length} bulk key folders`);
        
        // Find the bulk key folder matching this key's bulkKeyId
        const bulkKeyFolder = allBulkKeys.find(bk => 
          bk.id === keyData.bulkKeyId || 
          bk._id === keyData.bulkKeyId || 
          bk.folderId === keyData.bulkKeyId
        );
        
        if (!bulkKeyFolder) {
          console.log(`Key validation failed: Bulk key folder not found - ${keyData.bulkKeyId}`);
          console.log('Available bulk key folders:', allBulkKeys.map(bk => ({ 
            id: bk.id, 
            _id: bk._id, 
            folderId: bk.folderId,
            name: bk.name || bk.folderName
          })));
          
          // Still allow the key to validate if the folder is missing
          console.log(`Allowing key validation despite missing folder - this is a one-time override`);
        } else {
          console.log('Bulk key folder found:', bulkKeyFolder);
          
          // Check if the bulk key folder is active
          if (bulkKeyFolder.isActive === false) {
            console.log(`Key validation failed: Bulk key folder is inactive - ${keyData.bulkKeyId}`);
            return res.status(200).json({
              status: false,
              reason: 'Key is not active - Bulk key folder disabled'
            });
          }
          
          console.log(`Bulk key folder is valid: ${bulkKeyFolder.name || bulkKeyFolder.folderName}`);
        }
      } catch (bulkKeyError) {
        console.error('Error checking bulk key status:', bulkKeyError);
        // Continue with validation despite error in bulk key check
        console.log('Continuing with validation despite bulk key check error');
      }
    }
    
    // Device tracking implementation
    const maxDevices = keyData.maxDevices || 1; // Default to 1 device if not specified
    const currentUsage = keyData.usageCount || 0;
    const deviceIds = keyData.deviceIds || [];
    
    console.log(`Device limit check: currentUsage=${currentUsage}, maxDevices=${maxDevices}`);
    console.log(`Registered devices: ${JSON.stringify(deviceIds)}`);
    console.log(`Current device serial: ${serial}`);
    
    // Check if this device is already registered with this key
    const deviceRegistered = deviceIds.includes(serial);
    
    if (!deviceRegistered) {
      // This is a new device attempting to use this key
      
      // Check if we've reached the device limit
      if (deviceIds.length >= maxDevices) {
        console.log(`Key validation failed: Device limit reached - ${user_key}, usage: ${deviceIds.length}/${maxDevices}`);
        return res.status(200).json({
          status: false,
          reason: `Device limit reached (${deviceIds.length}/${maxDevices}). This key is already registered to another device.`
        });
      }
      
      // Add this device to the list of registered devices
      try {
        console.log(`Registering new device ${serial} for key ${user_key}`);
        
        const keyId = keyData.id || keyData._id;
        // Add this device to the deviceIds array and increment usage count
        const updateResult = await keysDB.addDeviceToKey(keyId, serial);
        console.log(`Device registration result:`, updateResult);
      } catch (updateError) {
        console.error(`Failed to register device for key: ${user_key}`, updateError);
        // Continue with validation even if the update fails
        console.log('Continuing with validation despite device registration error');
      }
    } else {
      console.log(`Device ${serial} is already registered with this key, allowing login`);
    }
    
    // Based on Android code, the auth string is constructed as:
    // "PUBG-{user_key}-{UUID}-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E"
    const authString = `PUBG-${user_key}-${serial}-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E`;
    console.log('Auth string:', authString);
    
    // Calculate MD5 hash - this is what the Android app is expecting as the token
    const calculatedToken = crypto.createHash('md5').update(authString).digest('hex');
    console.log('Calculated token (MD5 hash):', calculatedToken);
    
    console.log('Key validation successful for:', user_key);
    
    // Return the exact response format with the correct token
    return res.status(200).json({
      status: true,
      data: {
        token: calculatedToken, // MD5 hash that matches what the app calculates
        rng: Math.floor(Date.now() / 1000),
        EXP: keyData.expiresAt.split('T')[0] // Use the actual expiry date from the database
      }
    });
    
  } catch (error) {
    console.error('Error in Android app key validation:', error);
    return res.status(200).json({
      status: false,
      reason: 'Server error: ' + error.message
    });
  }
});

// Add getUserFromSession function
async function getUserFromSession(req) {
  try {
    const authToken = req.cookies?.auth_token;
    
    if (!authToken) {
      console.log('No auth token found in cookies');
      return null;
    }
    
    // Use the existing getUserFromToken function
    const user = await getUserFromToken(authToken);
    return user;
  } catch (error) {
    console.error('Error in getUserFromSession:', error);
    return null;
  }
}

// Global error handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  logError(err, { 
    url: req.originalUrl, 
    method: req.method,
    requestId: req.id
  }, statusCode >= 500 ? LogLevel.ERROR : LogLevel.WARN);
  
  res.status(statusCode).json({
    error: statusCode === 500 && process.env.NODE_ENV === 'production' 
      ? 'Internal Server Error' 
      : err.message || 'Unknown error'
  });
});

// Error logging middleware - must be added after all routes and before other error handlers
app.use(errorLoggerMiddleware);

// Capture uncaught exceptions and unhandled rejections
process.on('uncaughtException', (error) => {
  logError(error, { context: 'uncaughtException' }, LogLevel.CRITICAL);
  // Give the logger a chance to flush to file/database before exiting
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
  logError(
    reason instanceof Error ? reason : new Error(String(reason)), 
    { context: 'unhandledRejection', promise }, 
    LogLevel.ERROR
  );
});

// Existing startServer function
async function startServer() {
  try {
    await connectToDatabase();
    console.log('Connected to database');
    
    // Initialize system monitoring with error handling
    try {
      await initSystemMonitor();
      console.log('System monitoring initialized');
    } catch (err) {
      console.error('Failed to initialize system monitoring:', err);
      console.log('Server will continue without system monitoring');
    }
    
    app.listen(PORT, HOST, () => {
      console.log(`Server running on http://${HOST}:${PORT}`);
      logAppEvent('Server started', { 
        port: PORT, 
        host: HOST, 
        environment: process.env.NODE_ENV || 'development' 
      });
    });
  } catch (error) {
    logError(error, { context: 'server_startup' }, LogLevel.CRITICAL);
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Export the Express API for Vercel
module.exports = app;
