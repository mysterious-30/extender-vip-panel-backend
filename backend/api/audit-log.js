const express = require('express');
const router = express.Router();
const { logAuditEvent } = require('../lib/audit-logger');

/**
 * Handle audit log events from the frontend
 */
router.post('/audit-log', async (req, res) => {
  try {
    const auditData = req.body;
    
    // Basic validation
    if (!auditData || !auditData.action) {
      return res.status(400).json({ error: 'Invalid audit log data' });
    }

    // Extract client IP and user info
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const userId = req.user?.id || auditData.userId;

    // Log the audit event
    await logAuditEvent({
      action: auditData.action,
      category: auditData.category || 'user-action',
      status: auditData.status || 'success',
      details: auditData.details || {},
      target: auditData.target,
      clientInfo: {
        ip: clientIp,
        userAgent,
        userId,
        sessionId: auditData.sessionId,
        timestamp: auditData.timestamp || new Date()
      }
    });

    // Return success
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error handling audit log:', error);
    
    // Log the error but don't expose details to client
    return res.status(500).json({ error: 'Error processing audit log' });
  }
});

module.exports = router; 