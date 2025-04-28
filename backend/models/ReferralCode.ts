import mongoose, { Schema, Document } from 'mongoose';

export interface IReferralCode extends Document {
  code: string;
  generatedBy: mongoose.Types.ObjectId;
  expiryDate: Date;
  initialBalance: number;
  isUsed: boolean;
  usedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
}

const ReferralCodeSchema: Schema = new Schema({
  code: {
    type: String,
    required: true,
    unique: true,
  },
  generatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  expiryDate: {
    type: Date,
    required: true,
  },
  initialBalance: {
    type: Number,
    required: true,
    min: 0,
  },
  isUsed: {
    type: Boolean,
    default: false,
  },
  usedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Generate a unique referral code
ReferralCodeSchema.statics.generateUniqueCode = async function() {
  const generateRandomCode = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };
  
  let code = generateRandomCode();
  let codeExists = await this.findOne({ code });
  
  // Try up to 5 times to generate a unique code
  let attempts = 0;
  while (codeExists && attempts < 5) {
    code = generateRandomCode();
    codeExists = await this.findOne({ code });
    attempts++;
  }
  
  if (codeExists) {
    throw new Error('Failed to generate a unique referral code. Please try again.');
  }
  
  return code;
};

export default mongoose.models.ReferralCode || mongoose.model<IReferralCode>('ReferralCode', ReferralCodeSchema); 