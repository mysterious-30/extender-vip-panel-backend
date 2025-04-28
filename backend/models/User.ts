import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IUser extends Document {
  userId: string;
  password: string;
  role: 'owner';
  name?: string;
  balance: number;
  expiryDate?: Date;
  referralCode?: string;
  createdBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  comparePassword: (password: string) => Promise<boolean>;
}

const UserSchema: Schema = new Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['owner', 'admin', 'user'],
    default: 'admin',
  },
  name: {
    type: String,
  },
  balance: {
    type: Number,
    default: 0
  },
  expiryDate: {
    type: Date,
    // Use a simpler approach without accessing 'this'
    default: null
  },
  referralCode: {
    type: String,
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Set role-specific values before saving
UserSchema.pre('save', function(next) {
  // Set balance to Infinity for owner accounts
  if (this.role === 'owner') {
    this.balance = Infinity;
  }
  
  // Set expiry date for admin accounts (30 days)
  if (this.role === 'admin' && !this.expiryDate) {
    this.expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  }
  
  next();
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

// Method to compare password for login
UserSchema.methods.comparePassword = async function(password: string): Promise<boolean> {
  return bcrypt.compare(password, this.password);
};

// Create owner account if it doesn't exist
UserSchema.statics.createDefaultOwner = async function() {
  const ownerExists = await this.findOne({ userId: 'owner' });
  
  if (!ownerExists) {
    await this.create({
      userId: 'owner',
      password: 'owner123',
      role: 'owner',
      name: 'System Owner',
      balance: Infinity,
    });
    console.log('Default owner account created');
  }
};

export default mongoose.models.User || mongoose.model<IUser>('User', UserSchema);
