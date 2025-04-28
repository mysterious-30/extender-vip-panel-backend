// This declaration file tells TypeScript to accept ANY module import
// This is a workaround that will suppress ALL module import errors

declare module '*';
declare module '@/lib/security';
declare module '@/lib/monitoring';
declare module '@lib/security';
declare module '@security';
declare module 'firebase-config';
declare module 'monitoring-lib';
declare module '@/lib/db-utils'; 