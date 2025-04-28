const express = require('express');
const router = express.Router();
const { connectToDatabase } = require('../lib/mongodb');
const { logError, LogLevel } = require('../lib/error-logger');

/**
 * Handle performance metrics from the frontend
 */
router.post('/performance', async (req, res) => {
  try {
    const metricsData = req.body;
    
    // Basic validation
    if (!metricsData || !metricsData.page) {
      return res.status(400).json({ error: 'Invalid performance metrics data' });
    }

    // Add client IP and user agent if not already included
    if (!metricsData.userAgent) {
      metricsData.userAgent = req.headers['user-agent'];
    }
    
    if (!metricsData.ip) {
      metricsData.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    }
    
    // Add user ID if authenticated
    if (req.user && req.user.id) {
      metricsData.userId = req.user.id;
    }

    // Store metrics in database
    const { db } = await connectToDatabase();
    await db.collection('performance_metrics').insertOne({
      ...metricsData,
      receivedAt: new Date()
    });

    // Detect and log abnormal performance
    detectAbnormalPerformance(metricsData, db);

    // Return success
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error handling performance metrics:', error);
    logError(error, { context: 'performance_metrics_api' });
    
    // Don't expose error details to client
    return res.status(500).json({ error: 'Error processing performance metrics' });
  }
});

/**
 * Detect and log abnormal performance metrics
 * @param {Object} metrics - Performance metrics data
 * @param {Object} db - Database connection
 */
async function detectAbnormalPerformance(metrics, db) {
  try {
    // Define thresholds for abnormal performance
    const thresholds = {
      loadTime: 5000,  // 5 seconds 
      ttfb: 1000,      // 1 second
      fcp: 2000        // 2 seconds
    };
    
    let isAbnormal = false;
    const issues = [];
    
    // Check if metrics exceed thresholds
    if (metrics.loadTime > thresholds.loadTime) {
      isAbnormal = true;
      issues.push(`Slow page load: ${metrics.loadTime}ms`);
    }
    
    if (metrics.ttfb > thresholds.ttfb) {
      isAbnormal = true;
      issues.push(`Slow TTFB: ${metrics.ttfb}ms`);
    }
    
    if (metrics.fcp > thresholds.fcp) {
      isAbnormal = true;
      issues.push(`Slow FCP: ${metrics.fcp}ms`);
    }
    
    // If abnormal, log for analysis
    if (isAbnormal) {
      await db.collection('abnormal_performance').insertOne({
        timestamp: new Date(),
        page: metrics.page,
        issues,
        metrics,
        userAgent: metrics.userAgent,
        ip: metrics.ip,
        userId: metrics.userId
      });
      
      // Log to application logs as well
      console.warn('Abnormal performance detected:', {
        page: metrics.page,
        issues,
        metrics: {
          loadTime: metrics.loadTime,
          ttfb: metrics.ttfb,
          fcp: metrics.fcp
        }
      });
    }
  } catch (error) {
    console.error('Error detecting abnormal performance:', error);
  }
}

module.exports = router; 