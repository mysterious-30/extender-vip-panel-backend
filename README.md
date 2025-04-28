# Extender VIP Panel

A full-stack application with a frontend built in Next.js and a backend API built with Express.js.

## Project Structure

This repository contains both the frontend and backend code:

- `/frontend` - Next.js application with React components
- `/backend` - Express.js API server with MongoDB integration

## Getting Started

### Prerequisites

- Node.js 18.x or higher
- MongoDB instance (local or Atlas)
- npm or yarn

### Setup

1. Clone the repository:

```bash
git clone https://github.com/mysterious-30/extender-vip-panel-backend.git
cd extender-vip-panel-backend
```

2. Install dependencies for both frontend and backend:

```bash
# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

3. Set up environment variables:

Create the following `.env` files:

**Backend (.env)**
```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
COOKIE_SECRET=your_cookie_secret
API_KEY_SECRET=your_api_key_secret
NODE_ENV=development
```

**Frontend (.env.local)**
```
NEXT_PUBLIC_API_URL=http://localhost:3001
NEXT_PUBLIC_ENVIRONMENT=development
```

4. Run the development servers:

```bash
# Run backend (from backend directory)
npm run dev

# Run frontend (from frontend directory)
npm run dev
```

## Deployment

### Backend Deployment (Vercel)

The backend is configured for deployment to Vercel. Key features:

- Serverless functions for API endpoints
- Automatic TypeScript compilation
- Middleware for CORS, security, and performance
- MongoDB connection handling

See `backend/vercel-deployment-guide.md` for detailed deployment instructions.

### Frontend Deployment (Vercel)

The frontend is optimized for Vercel deployment with:

- Static site generation where possible
- API routes for server-side operations
- Optimized image handling
- Environment variable configuration

## License

[MIT License](LICENSE) 