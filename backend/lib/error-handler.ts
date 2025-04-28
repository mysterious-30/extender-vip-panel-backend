import { NextRequest, NextResponse } from 'next/server';
import { logSecurityEvent } from './monitoring';
import { LogLevel, SecurityEventType } from './monitoring';

export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 500,
    public isOperational: boolean = true,
    public context: Record<string, unknown> = {}
  ) {
    super(message);
    Error.captureStackTrace(this, this.constructor);
  }
}

export function setupGlobalErrorHandlers() {
  process.on('uncaughtException', (error) => {
    handleError(error);
    if (!error.isOperational) {
      process.exit(1);
    }
  });

  process.on('unhandledRejection', (reason) => {
    handleError(reason instanceof Error ? reason : new Error(String(reason)));
  });
}

export async function handleError(error: Error | AppError, req?: NextRequest) {
  let errorType = error.constructor.name;
  let errorMessage = error.message;
  let statusCode = 500;
  let isOperational = false;
  let errorContext = {};

  if (error instanceof AppError) {
    statusCode = error.statusCode;
    isOperational = error.isOperational;
    errorContext = error.context;
  }

  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction && !isOperational) {
    errorMessage = 'An unexpected error occurred';
    errorContext = {};
  }

  // Log the error
  await logSecurityEvent({
    level: LogLevel.ERROR,
    eventType: SecurityEventType.ERROR,
    message: errorMessage,
    metadata: {
      errorType,
      statusCode,
      isOperational,
      context: errorContext,
      stack: isProduction ? undefined : error.stack,
      url: req?.url,
      method: req?.method
    }
  });

  // Return error response if in API context
  if (req) {
    return NextResponse.json(
      {
        error: errorMessage,
        ...(isProduction ? {} : { details: errorContext })
      },
      { status: statusCode }
    );
  }
}

export function createErrorHandler(handler: Function) {
  return async (req: NextRequest, ...args: any[]) => {
    try {
      return await handler(req, ...args);
    } catch (error) {
      return handleError(error instanceof Error ? error : new Error(String(error)), req);
    }
  };
} 




