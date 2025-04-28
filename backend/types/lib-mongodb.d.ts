declare module '@/lib/mongodb' {
  import { Db, MongoClient } from 'mongodb';
  
  export function connectToDatabase(): Promise<{
    client: MongoClient;
    db: Db;
  }>;
} 