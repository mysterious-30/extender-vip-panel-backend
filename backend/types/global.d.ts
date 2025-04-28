// This declaration file tells TypeScript to accept any module import
// This is a workaround to avoid adding type declarations for all the modules

declare module 'next/server' {
  export class NextResponse extends Response {
    static json(data: any, init?: ResponseInit): NextResponse;
    static redirect(url: string | URL, status?: number): NextResponse;
    static error(): NextResponse;
    static rewrite(url: string | URL, init?: ResponseInit): NextResponse;
    static next(init?: ResponseInit): NextResponse;
  }
  
  export interface NextRequest extends Request {
    nextUrl: URL;
    cookies: {
      get(name: string): { name: string, value: string } | undefined;
    };
  }
}

declare module 'next/headers' {
  export function cookies(): {
    get(name: string): { value: string } | undefined;
    set(name: string, value: string, options?: any): void;
    delete(name: string): void;
  };
}

declare module '@/lib/mongodb' {
  import { MongoClient, Db } from 'mongodb';
  export function connectToDatabase(): Promise<{
    client: MongoClient;
    db: Db;
  }>;
}

declare module '@/lib/mongodb-connect' {
  export function connectDB(): Promise<any>;
}

declare module '@/lib/auth' {
  export function verifyAuth(token: string | Request): Promise<any>;
}

declare module '@/models/User' {
  import mongoose from 'mongoose';
  const UserModel: mongoose.Model<any>;
  export default UserModel;
}

declare module '@/models/Key' {
  import mongoose from 'mongoose';
  
  export interface IKey {
    key: string;
    isActive: boolean;
    createdAt: Date;
    expiresAt: Date;
    createdBy: mongoose.Types.ObjectId | string;
    deviceId?: string;
    deviceIds?: string[];
    lastUsedAt?: Date;
    usageCount: number;
    maxDevices: number;
    isBulkKey: boolean;
    bulkGroupId?: string;
    status: 'active' | 'inactive' | 'expired';
  }
  
  const KeyModel: mongoose.Model<IKey>;
  export default KeyModel;
}

// Extend Express Request interface
declare namespace Express {
  interface Request {
    user?: any;
  }
}

declare module '@/lib/monitoring' {
  export function logSecurityEvent(event: any): void;
  export enum SecurityEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    REGISTER,
    PASSWORD_RESET,
    ACCOUNT_LOCKED,
    PERMISSION_DENIED
  }
  export enum LogLevel {
    INFO,
    WARN,
    ERROR,
    DEBUG
  }
}

declare module 'bcryptjs' {
  export function hash(data: string, saltOrRounds: string | number): Promise<string>;
  export function compare(data: string, encrypted: string): Promise<boolean>;
}

declare module 'next-auth/jwt' {
  export function getToken(options: any): Promise<any>;
}

declare module '@/models/key' {
  import mongoose from 'mongoose';
  
  export interface IKey {
    key: string;
    isActive: boolean;
    createdAt: Date;
    expiresAt: Date;
    createdBy: mongoose.Types.ObjectId | string;
    deviceId?: string;
    deviceIds?: string[];
    lastUsedAt?: Date;
    usageCount: number;
    maxDevices: number;
    isBulkKey: boolean;
    bulkGroupId?: string;
    status: 'active' | 'inactive' | 'expired';
  }
  
  export const Key: mongoose.Model<IKey>;
}

declare module '@upstash/redis' {
  export class Redis {
    constructor(options: any);
    get(key: string): Promise<any>;
    set(key: string, value: any, options?: any): Promise<any>;
    del(key: string): Promise<any>;
  }
} 