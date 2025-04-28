// This file is now replaced by declarations in global.d.ts
// Do not use this file anymore.

declare module 'next/headers' {
  export interface Cookie {
    name: string;
    value: string;
  }

  export function cookies(): {
    get: (name: string) => Cookie | undefined;
    getAll: () => Cookie[];
    set: (cookie: Cookie) => void;
    delete: (name: string) => void;
  };
} 