import { collection, query, where, getDocs, addDoc, updateDoc, doc, getDoc, Timestamp, orderBy, limit } from 'firebase/firestore';
import { db } from './firebase';
import { v4 as uuidv4 } from 'uuid';
import { getUserIdByKey } from './db-utils';

interface APITokenData {
  id?: string;
  name: string;
  token: string;
  userId: string;
  createdAt: Date;
  lastUsed: Date | null;
  expiryDate: Date;
  isActive: boolean;
}

class APITokenOperations {
  static async generateToken(userId: string, name: string, expiryDays: number = 30): Promise<APITokenData | null> {
    try {
      // Check if a token with the same name already exists for this user
      const tokensRef = collection(db, 'apiTokens');
      const q = query(tokensRef, 
        where('userId', '==', userId),
        where('name', '==', name),
        where('isActive', '==', true)
      );
      
      const snapshot = await getDocs(q);
      if (!snapshot.empty) {
        throw new Error('A token with this name already exists');
      }
      
      // Generate a unique token
      const token = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
      
      // Calculate expiry date
      const now = new Date();
      const expiryDate = new Date();
      expiryDate.setDate(now.getDate() + expiryDays);
      
      // Create the token data
      const tokenData: APITokenData = {
        name,
        token,
        userId,
        createdAt: now,
        lastUsed: null,
        expiryDate,
        isActive: true
      };
      
      // Save to Firestore
      const docRef = await addDoc(collection(db, 'apiTokens'), tokenData);
      
      // Return the token with its ID
      return {
        ...tokenData,
        id: docRef.id
      };
    } catch (error) {
      console.error('Error generating API token:', error);
      throw error;
    }
  }
  
  static async listTokens(userId: string): Promise<APITokenData[]> {
    try {
      const tokensRef = collection(db, 'apiTokens');
      const q = query(tokensRef, 
        where('userId', '==', userId),
        orderBy('createdAt', 'desc')
      );
      
      const snapshot = await getDocs(q);
      if (snapshot.empty) {
        return [];
      }
      
      return snapshot.docs.map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          name: data.name,
          token: data.token,
          userId: data.userId,
          createdAt: data.createdAt.toDate(),
          lastUsed: data.lastUsed ? data.lastUsed.toDate() : null,
          expiryDate: data.expiryDate.toDate(),
          isActive: data.isActive
        };
      });
    } catch (error) {
      console.error('Error listing API tokens:', error);
      throw error;
    }
  }
  
  static async revokeToken(tokenId: string, userId: string): Promise<boolean> {
    try {
      // Get the token
      const tokenDoc = doc(db, 'apiTokens', tokenId);
      const tokenSnapshot = await getDoc(tokenDoc);
      
      if (!tokenSnapshot.exists()) {
        throw new Error('Token not found');
      }
      
      const tokenData = tokenSnapshot.data();
      
      // Check if the token belongs to the user
      if (tokenData.userId !== userId) {
        throw new Error('Unauthorized to revoke this token');
      }
      
      // Check if the token is already revoked
      if (!tokenData.isActive) {
        throw new Error('Token is already revoked');
      }
      
      // Revoke the token
      await updateDoc(tokenDoc, {
        isActive: false
      });
      
      return true;
    } catch (error) {
      console.error('Error revoking API token:', error);
      throw error;
    }
  }
  
  static async verifyToken(apiToken: string): Promise<{ userId: string; tokenId: string } | null> {
    try {
      const tokensRef = collection(db, 'apiTokens');
      const q = query(tokensRef, 
        where('token', '==', apiToken),
        where('isActive', '==', true),
        limit(1)
      );
      
      const snapshot = await getDocs(q);
      if (snapshot.empty) {
        return null;
      }
      
      const tokenDoc = snapshot.docs[0];
      const tokenData = tokenDoc.data();
      
      // Check if token has expired
      const expiryDate = tokenData.expiryDate.toDate();
      if (expiryDate < new Date()) {
        // Automatically revoke expired tokens
        await updateDoc(doc(db, 'apiTokens', tokenDoc.id), {
          isActive: false
        });
        return null;
      }
      
      // Update last used timestamp
      await updateDoc(doc(db, 'apiTokens', tokenDoc.id), {
        lastUsed: Timestamp.now()
      });
      
      return {
        userId: tokenData.userId,
        tokenId: tokenDoc.id
      };
    } catch (error) {
      console.error('Error verifying API token:', error);
      return null;
    }
  }
  
  static async getUserInfoFromToken(apiToken: string): Promise<any | null> {
    try {
      const tokenInfo = await this.verifyToken(apiToken);
      if (!tokenInfo) {
        return null;
      }
      
      // Get user info
      const usersRef = collection(db, 'users');
      const q = query(usersRef, where('userId', '==', tokenInfo.userId));
      const userSnapshot = await getDocs(q);
      
      if (userSnapshot.empty) {
        return null;
      }
      
      const userData = userSnapshot.docs[0].data();
      
      // Get balance from keys collection
      const keysRef = collection(db, 'keys');
      const keysQuery = query(keysRef, where('userIdField', '==', tokenInfo.userId));
      const keysSnapshot = await getDocs(keysQuery);
      
      let balance = 0;
      if (!keysSnapshot.empty) {
        balance = keysSnapshot.docs.reduce((total, doc) => {
          const keyData = doc.data();
          return total + (keyData.balance || 0);
        }, 0);
      }
      
      return {
        userId: userData.userId,
        userIdField: userData.userId, // For compatibility with existing code
        email: userData.email,
        role: userData.role,
        balance,
        tokenId: tokenInfo.tokenId
      };
    } catch (error) {
      console.error('Error getting user info from token:', error);
      return null;
    }
  }
}

export default APITokenOperations; 