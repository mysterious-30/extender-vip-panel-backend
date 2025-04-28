declare module '@/lib/mongodb' {
  import { MongoClient, Db } from 'mongodb';
  
  export function connectToDatabase(): Promise<{
    client: MongoClient;
    db: Db;
  }>;
  
  export function connectDB(): Promise<any>;
  
  export const client: MongoClient;
  export const db: Db;
}

declare interface IKeyModel {
  findById(id: string): Promise<any>;
  findOne(query: any): Promise<any>;
  find(query: any): any;
  findByIdAndDelete(id: string): Promise<any>;
  countDocuments(query: any): Promise<number>;
  updateMany(query: any, update: any): Promise<any>;
  deleteMany(query: any): Promise<any>;
  insertMany(docs: any[]): Promise<any>;
  updateOne(query: any, update: any): Promise<any>;
} 