const { logAuditEvent } = require('../lib/audit-logger');
const { connectDB, closeDB } = require('../lib/db');

describe('Audit Logger', () => {
  let db;
  
  beforeAll(async () => {
    // Connect to the database before running tests
    db = await connectDB();
  });
  
  afterAll(async () => {
    // Clean up test data
    if (db) {
      await db.collection('auditLogs').deleteMany({ 
        category: 'TEST' 
      });
      
      // Close the database connection after tests
      await closeDB();
    }
  });
  
  test('should log an audit event successfully', async () => {
    const eventData = {
      action: 'TEST_ACTION',
      category: 'TEST',
      details: {
        testProperty: 'test value',
        testNumber: 123
      },
      clientInfo: {
        userId: 'test-user-id',
        username: 'testuser',
        ipAddress: '127.0.0.1',
        userAgent: 'Test User Agent'
      }
    };
    
    const result = await logAuditEvent(eventData);
    
    // Verify the audit log was created with expected properties
    expect(result).toBeDefined();
    expect(result._id).toBeDefined();
    expect(result.action).toBe(eventData.action);
    expect(result.category).toBe(eventData.category);
    expect(result.details).toEqual(eventData.details);
    expect(result.clientInfo).toEqual(eventData.clientInfo);
    expect(result.timestamp).toBeDefined();
  });
  
  test('should reject audit event with missing required fields', async () => {
    const incompleteEvent = {
      action: 'TEST_ACTION',
      // Missing category
      clientInfo: {
        userId: 'test-user-id'
        // Missing other client info
      }
    };
    
    await expect(logAuditEvent(incompleteEvent)).rejects.toThrow();
  });
  
  test('should find logged audit events in the database', async () => {
    const eventData = {
      action: 'QUERY_TEST',
      category: 'TEST',
      details: { test: 'querying' },
      clientInfo: {
        userId: 'test-query-user',
        username: 'queryuser',
        ipAddress: '127.0.0.1',
        userAgent: 'Test Query Agent'
      }
    };
    
    // Log a test event
    const result = await logAuditEvent(eventData);
    
    // Find the event in the database
    const collection = db.collection('auditLogs');
    const foundEvent = await collection.findOne({ _id: result._id });
    
    // Verify the event was stored correctly
    expect(foundEvent).toBeDefined();
    expect(foundEvent.action).toBe(eventData.action);
    expect(foundEvent.category).toBe(eventData.category);
    expect(foundEvent.details).toEqual(eventData.details);
  });
}); 