# AllerSafe Backend - Railway Deployment

This is the FastAPI backend for AllerSafe, an allergy-safe dining platform.

## Quick Railway Deployment

1. **Fork/clone this repository**
2. **Connect to Railway**: https://railway.app
3. **Environment Variables**: Copy from `.env.example` and configure in Railway dashboard
4. **Deploy**: Railway will automatically detect and deploy using `Procfile`

## Key Files

- `main.py` - FastAPI application entry point
- `Procfile` - Railway start command
- `railway.json` - Railway deployment configuration  
- `requirements.txt` - Python dependencies
- `.env.example` - Environment variables template

## Environment Variables Required

See `.env.example` for all required environment variables. Configure these in Railway dashboard:

- `MONGO_URL` - MongoDB connection string
- `STRIPE_API_KEY` - Stripe secret key
- `TWILIO_ACCOUNT_SID` - Twilio account SID
- `JWT_SECRET` - Secure random string for JWT tokens
- And more...

## API Documentation

Once deployed, visit: `https://your-app.up.railway.app/docs`

## Health Check

Health endpoint: `https://your-app.up.railway.app/api/health`

## Features

- Consumer menu scanning with allergen detection
- Stripe payment integration for premium subscriptions  
- Twilio SMS emergency alerts
- Admin analytics dashboard
- Restaurant menu management
- Family profile management

Built with FastAPI, MongoDB, and integrated with Stripe, Twilio, and SendGrid.