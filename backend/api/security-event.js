const express = require('express');
const router = express.Router();
const { logSecurityEvent } = require('../lib/security-logger');

/**
 * Handle security event logs from the frontend
 */
router.post('/security-event', async (req, res) => {
  try {
    const eventData = req.body;
    
    // Basic validation
    if (!eventData || !eventData.type) {
      return res.status(400).json({ error: 'Invalid security event data' });
    }

    // Extract client IP and user info
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const userId = req.user?.id;

    // Log the security event
    await logSecurityEvent({
      type: eventData.type,
      severity: eventData.severity || 'medium',
      description: eventData.description || '',
      source: 'client',
      metadata: eventData.metadata || {},
      clientInfo: {
        ip: clientIp,
        userAgent,
        userId,
        url: eventData.url,
        timestamp: eventData.timestamp || new Date()
      }
    });

    // Return success
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error handling security event:', error);
    
    // Log the error but don't expose details to client
    return res.status(500).json({ error: 'Error processing security event' });
  }
});

module.exports = router; 