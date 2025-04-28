# Vercel Deployment Guide for Extender VIP Panel Backend

This guide provides instructions for deploying the backend API to Vercel.

## Environment Variables

Set the following environment variables in your Vercel project settings:

| Variable | Example Value | Description |
|----------|--------------|-------------|
| `MONGODB_URI` | `mongodb+srv://username:password@cluster.mongodb.net/database?retryWrites=true&w=majority` | MongoDB connection string |
| `JWT_SECRET` | `your-secure-jwt-secret-key` | Secret key for JWT token generation/validation |
| `COOKIE_SECRET` | `your-secure-cookie-secret` | Secret for encrypting cookies |
| `API_KEY_SECRET` | `your-api-key-secret` | Secret for API key generation |
| `NODE_ENV` | `production` | Environment mode |
| `CORS_ORIGIN` | `https://your-frontend-domain.vercel.app` | Frontend domain for CORS |

## Setting Up Environment Variables in Vercel

1. Go to your Vercel dashboard
2. Select your backend project
3. Click on "Settings" tab
4. Select "Environment Variables" from the sidebar
5. Add each of the variables listed above with their corresponding values
6. Make sure they're applied to all environments (Production, Preview, Development)

## Connection to Frontend

Ensure that your frontend application is configured to connect to your deployed backend API. Update the following in your frontend configuration:

1. Set the `NEXT_PUBLIC_API_URL` environment variable to your deployed backend URL
2. Ensure CORS is properly configured to allow requests from your frontend domain

## Deployment Configuration

The current configuration in `vercel.json` is set up to:

- Deploy the application using Node.js runtime
- Include all necessary files in the deployment
- Set up proper routing for the API endpoints
- Configure CORS headers for cross-origin requests

## Troubleshooting

If you encounter build issues:

1. Check the build logs for specific error messages
2. Ensure all environment variables are correctly set
3. Verify that the MongoDB URI is valid and accessible from Vercel's servers
4. Check that dependencies are correctly listed in package.json

## Security Considerations

- Use strong, unique secrets for JWT_SECRET, COOKIE_SECRET, and API_KEY_SECRET
- Do not commit environment variables to your repository
- Limit CORS to only necessary origins
- Consider implementing rate limiting for public endpoints 