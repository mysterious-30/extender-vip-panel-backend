import mongoose, { Schema, Document, Model } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

// Basic Key Document Interface
export interface IKey extends Document {
  key: string;
  isActive: boolean;
  createdAt: Date;
  expiresAt: Date;
  createdBy: mongoose.Types.ObjectId | string;
  deviceId?: string;
  lastUsedAt?: Date;
  usageCount: number;
  maxDevices: number;
  isBulkKey: boolean;
  bulkGroupId?: string;
  status: 'active' | 'inactive' | 'expired';
  
  // Methods
  canUseOnDevice(deviceId: string): Promise<boolean>;
  assignToDevice(deviceId: string): Promise<boolean>;
}

// Interface for Key Model with static methods
export interface IKeyModel extends Model<IKey> {
  generateUniqueKey(): Promise<string>;
  generateBulkKeys(count: number, options: {
    expiresAt: Date;
    createdBy: string | mongoose.Types.ObjectId;
    maxDevices?: number;
  }): Promise<IKey[]>;
}

// Key Schema
const KeySchema = new Schema<IKey, IKeyModel>({
  key: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  deviceId: {
    type: String,
    index: true,
    sparse: true
  },
  lastUsedAt: {
    type: Date
  },
  usageCount: {
    type: Number,
    default: 0
  },
  maxDevices: {
    type: Number,
    default: 1
  },
  isBulkKey: {
    type: Boolean,
    default: false,
    index: true
  },
  bulkGroupId: {
    type: String,
    index: true,
    sparse: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'expired'],
    required: true
  }
});

// Method to check if a key can be used on a device
KeySchema.methods.canUseOnDevice = async function(deviceId: string): Promise<boolean> {
  try {
    // Check if key is active
    if (!this.isActive) {
      console.log(`Key ${this.key} is inactive`);
      return false;
    }
    
    // Check if key is expired
    if (this.expiresAt < new Date()) {
      console.log(`Key ${this.key} has expired`);
      return false;
    }
    
    // If the key is already assigned to this device, allow it
    if (this.deviceId && this.deviceId === deviceId) {
      return true;
    }
    
    // If the key is already assigned to another device, don't allow it
    if (this.deviceId && this.deviceId !== deviceId) {
      console.log(`Key ${this.key} is already assigned to device ${this.deviceId}`);
      return false;
    }
    
    // New device assignment - check if we're within maxDevices limit
    if (!this.deviceId && this.usageCount < this.maxDevices) {
      return true;
    }
    
    console.log(`Key ${this.key} cannot be used on this device`);
    return false;
  } catch (error) {
    console.error('Error checking device usage:', error);
    return false;
  }
};

// Method to assign a key to a device
KeySchema.methods.assignToDevice = async function(deviceId: string): Promise<boolean> {
  try {
    // Check if key can be used on this device
    const canUse = await this.canUseOnDevice(deviceId);
    
    if (!canUse) {
      return false;
    }
    
    // If it's already assigned to this device, just update the usage
    if (this.deviceId === deviceId) {
      this.lastUsedAt = new Date();
      await this.save();
      return true;
    }
    
    // Assign to the device
    this.deviceId = deviceId;
    this.lastUsedAt = new Date();
    this.usageCount += 1;
    
    await this.save();
    return true;
  } catch (error) {
    console.error('Error assigning key to device:', error);
    return false;
  }
};

// Static method to generate a unique key
KeySchema.statics.generateUniqueKey = async function(): Promise<string> {
  const keyLength = 16;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  
  for (let i = 0; i < keyLength; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  // Add dashes for readability
  key = `${key.slice(0, 4)}-${key.slice(4, 8)}-${key.slice(8, 12)}-${key.slice(12, 16)}`;
  
  // Check if the key already exists
  const keyExists = await this.findOne({ key });
  
  if (keyExists) {
    // If the key already exists, generate a new one recursively
    return this.generateUniqueKey();
  }
  
  return key;
};

// Static method to generate bulk keys
KeySchema.statics.generateBulkKeys = async function(
  count: number, 
  options: { 
    expiresAt: Date; 
    createdBy: string | mongoose.Types.ObjectId;
    maxDevices?: number;
  }
): Promise<IKey[]> {
  try {
    if (count <= 0 || count > 100) {
      throw new Error('Invalid key count. Must be between 1 and 100.');
    }
    
    const bulkGroupId = uuidv4();
    const keys: IKey[] = [];
    
    for (let i = 0; i < count; i++) {
      const key = await this.generateUniqueKey();
      
      const keyDoc = new this({
        key,
        isActive: true,
        expiresAt: options.expiresAt,
        createdBy: options.createdBy,
        maxDevices: options.maxDevices || 1,
        isBulkKey: true,
        bulkGroupId,
        usageCount: 0,
        status: 'active'
      });
      
      await keyDoc.save();
      keys.push(keyDoc);
    }
    
    return keys;
  } catch (error) {
    console.error('Error generating bulk keys:', error);
    throw error;
  }
};

// Initialize the model (or get it if it's already initialized)
const Key = (mongoose.models.Key || mongoose.model<IKey, IKeyModel>('Key', KeySchema)) as IKeyModel;

export default Key;

// Add a method to check if a key is expired
export const isKeyExpired = (key: IKey): boolean => {
  return new Date() > new Date(key.expiresAt);
};

// Update the canUseOnDevice method to check for expired status
export const canUseOnDevice = async (key: IKey, deviceId: string): Promise<boolean> => {
  // If key is expired or inactive, it cannot be used
  if (key.status !== 'active') {
    return false;
  }
  
  // Check if key is expired
  if (isKeyExpired(key)) {
    return false;
  }
  
  // ... existing device check logic ...
  return true;
}; 