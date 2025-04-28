const express = require('express');
const router = express.Router();
const { connectToDatabase } = require('../lib/mongodb');
const { logError, LogLevel } = require('../lib/error-logger');
const { logAbnormalActivity } = require('../lib/system-monitor');

/**
 * Handle user interaction events from the frontend
 */
router.post('/user-interaction', async (req, res) => {
  try {
    const interactionData = req.body;
    
    // Basic validation
    if (!interactionData || !interactionData.action || !interactionData.target) {
      return res.status(400).json({ error: 'Invalid user interaction data' });
    }

    // Add client IP and user agent if not already included
    if (!interactionData.ip) {
      interactionData.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    }
    
    if (!interactionData.userAgent) {
      interactionData.userAgent = req.headers['user-agent'];
    }
    
    // Add user ID if authenticated
    if (req.user && req.user.id && !interactionData.userId) {
      interactionData.userId = req.user.id;
    }

    // Store interaction in database
    const { db } = await connectToDatabase();
    await db.collection('user_interactions').insertOne({
      ...interactionData,
      receivedAt: new Date()
    });

    // Check for suspicious activity patterns
    await detectSuspiciousActivity(interactionData, db);

    // Return success
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error handling user interaction:', error);
    logError(error, { context: 'user_interaction_api' });
    
    // Don't expose error details to client
    return res.status(500).json({ error: 'Error processing user interaction' });
  }
});

/**
 * Detect suspicious user activity patterns
 * @param {Object} interaction - User interaction data
 * @param {Object} db - Database connection
 */
async function detectSuspiciousActivity(interaction, db) {
  try {
    // Define patterns for suspicious activity
    const suspiciousPatterns = [
      { action: 'click', target: /^admin|security|config|token/, sensitive: true },
      { action: 'submit', target: /login|register|password/, sensitive: true },
      { action: 'navigate', target: /admin|settings|billing/, sensitive: true }
    ];
    
    // Check if this interaction matches a sensitive pattern
    const isSensitiveAction = suspiciousPatterns.some(pattern => 
      interaction.action === pattern.action && 
      pattern.target.test(interaction.target) && 
      pattern.sensitive
    );
    
    if (isSensitiveAction) {
      // Check frequency of this action from this user/IP
      const oneMinuteAgo = new Date(Date.now() - 60 * 1000);
      
      const query = {
        timestamp: { $gte: oneMinuteAgo },
        action: interaction.action,
        target: interaction.target,
        $or: [
          { userId: interaction.userId },
          { ip: interaction.ip }
        ]
      };
      
      const count = await db.collection('user_interactions').countDocuments(query);
      
      // If unusually high frequency of sensitive actions (more than 10 in a minute)
      if (count > 10) {
        // Log as abnormal activity
        await logAbnormalActivity('suspicious_ui_activity', 'High frequency of sensitive user interactions', {
          action: interaction.action,
          target: interaction.target,
          userId: interaction.userId,
          ip: interaction.ip,
          count,
          timeWindow: '1 minute'
        });
      }
    }
    
    // Check for unusual navigation patterns (e.g., skipping expected flows)
    if (interaction.action === 'navigate') {
      // Implementation would depend on your application's expected flows
      // For now, just log unusual direct access to certain pages
      const restrictedPages = ['/admin/keys', '/admin/settings', '/admin/users'];
      
      if (restrictedPages.includes(interaction.target) && 
          (!interaction.metadata || !interaction.metadata.referrer)) {
        
        await logAbnormalActivity('direct_page_access', 'Direct access to restricted page', {
          page: interaction.target,
          userId: interaction.userId,
          ip: interaction.ip,
          sessionId: interaction.sessionId
        });
      }
    }
  } catch (error) {
    console.error('Error detecting suspicious activity:', error);
  }
}

module.exports = router; 