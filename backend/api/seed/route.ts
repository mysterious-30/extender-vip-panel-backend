// @ts-ignore - Ignore missing type declarations
import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/mongodb';
import bcrypt from 'bcryptjs';

export async function GET() {
  try {
    const { db } = await connectToDatabase();
    
    // Check if users collection exists and has any documents
    const usersCollection = db.collection('users');
    const userCount = await usersCollection.countDocuments();
    
    if (userCount === 0) {
      // Create a default owner account with a secure password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('owner123', salt);
      
      await usersCollection.insertOne({
        userId: 'owner',
        password: hashedPassword,
        role: 'owner',
        name: 'System Owner',
        balance: 999999,
        createdAt: new Date()
      });
      
      return NextResponse.json({
        success: true,
        message: 'Database initialized successfully with default owner account.'
      });
    }
    
    return NextResponse.json({
      success: true,
      message: 'Database already has users, no initialization needed'
    });
  } catch (error) {
    console.error('Seed error:', error);
    return NextResponse.json(
      { success: false, message: 'Failed to initialize database' },
      { status: 500 }
    );
  }
} 
