// Simple Express server with minimal dependencies
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3002;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Log requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth endpoints
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // Simple hardcoded authentication
  if (
    (username === 'admin' && password === 'admin123') ||
    (username === 'user' && password === 'user123') ||
    (username === 'owner' && password === 'owner123')
  ) {
    // Determine role based on username
    const role = username;
    
    // Set authentication cookie
    res.cookie('authToken', JSON.stringify({ username, role }), {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({ 
      success: true, 
      user: { 
        username, 
        role,
        name: username.charAt(0).toUpperCase() + username.slice(1),
        email: `${username}@example.com`
      }
    });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

app.get('/api/auth/check-session', (req, res) => {
  try {
    const authToken = req.cookies.authToken;
    
    if (!authToken) {
      return res.status(401).json({ 
        authenticated: false, 
        message: 'No authentication token found' 
      });
    }
    
    const userData = JSON.parse(authToken);
    
    res.json({ 
      authenticated: true, 
      user: {
        username: userData.username,
        role: userData.role,
        name: userData.username.charAt(0).toUpperCase() + userData.username.slice(1),
        email: `${userData.username}@example.com`
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(401).json({ 
      authenticated: false, 
      message: 'Invalid session' 
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('authToken');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Dashboard data
app.get('/api/dashboard/stats', (req, res) => {
  try {
    const authToken = req.cookies.authToken;
    
    if (!authToken) {
      return res.status(401).json({ 
        success: false, 
        message: 'Not authenticated' 
      });
    }
    
    const userData = JSON.parse(authToken);
    const role = userData.role;
    
    // Different stats based on role
    let stats = {
      activeUsers: 253,
      totalProjects: 85,
      totalTasks: 342,
      completedTasks: 187
    };
    
    // Add role-specific data
    if (role === 'admin' || role === 'owner') {
      stats.pendingApprovals = 24;
      stats.systemHealth = 98;
      stats.recentSignups = 14;
    }
    
    if (role === 'owner') {
      stats.revenue = 128750;
      stats.growth = 12.7;
      stats.conversionRate = 8.4;
    }
    
    res.json({ success: true, stats });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching dashboard stats' 
    });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
  console.log('Available endpoints:');
  console.log('  - GET  /api/health');
  console.log('  - POST /api/auth/login');
  console.log('  - GET  /api/auth/check-session');
  console.log('  - POST /api/auth/logout');
  console.log('  - GET  /api/dashboard/stats');
}); 