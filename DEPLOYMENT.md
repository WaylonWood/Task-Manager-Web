# Task Manager Web - Vercel Deployment Guide

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
2. **GitHub Repository**: Push your code to GitHub
3. **Database**: Set up a PostgreSQL database (recommended services: Neon, Supabase, or Railway)

## Deployment Steps

### 1. Prepare Your Database

Since Vercel doesn't support persistent SQLite databases, you'll need a PostgreSQL database:

**Option A: Neon (Recommended)**
- Go to [neon.tech](https://neon.tech) and create a free account
- Create a new database
- Copy the connection string

**Option B: Supabase**
- Go to [supabase.com](https://supabase.com) and create a project
- Go to Settings > Database and copy the connection string

**Option C: Railway**
- Go to [railway.app](https://railway.app) and create a PostgreSQL database
- Copy the connection string

### 2. Deploy to Vercel

1. **Connect Repository**:
   - Go to [vercel.com/dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your GitHub repository

2. **Configure Environment Variables**:
   In Vercel dashboard, go to Settings > Environment Variables and add:
   ```
   SECRET_KEY=your-super-secret-production-key-here
   DATABASE_URL=postgresql://username:password@host:port/database
   FLASK_ENV=production
   ENV=production
   ```

3. **Deploy**:
   - Click "Deploy"
   - Vercel will automatically detect the `vercel.json` configuration

### 3. Initialize Database

After the first deployment, you need to run database migrations:

1. **Option A: Use Vercel CLI**:
   ```bash
   npm i -g vercel
   vercel login
   vercel env pull .env.local
   python -m flask db upgrade
   ```

2. **Option B: Run migrations locally**:
   - Set the production DATABASE_URL in your local environment
   - Run: `flask db upgrade`

### 4. File Upload Considerations

⚠️ **Important**: Vercel has a read-only filesystem. User uploads won't persist between deployments.

**Solutions**:
- **Cloud Storage**: Use AWS S3, Cloudinary, or similar
- **Vercel Blob**: Use Vercel's blob storage service

### 5. Rate Limiting (Optional)

For production rate limiting, consider using Redis:
- Add `RATELIMIT_STORAGE_URI=redis://your-redis-url` to environment variables
- Use services like Upstash Redis

## Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask secret key for sessions | Yes |
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `FLASK_ENV` | Set to "production" | Yes |
| `ENV` | Set to "production" | Yes |
| `RATELIMIT_STORAGE_URI` | Redis URL for rate limiting | No |

## Post-Deployment Checklist

- [ ] Database migrations completed
- [ ] Static files loading correctly
- [ ] User registration/login working
- [ ] File uploads handled (cloud storage setup)
- [ ] Environment variables configured
- [ ] SSL certificate active (automatic with Vercel)
- [ ] Custom domain configured (if needed)

## Troubleshooting

**Database Connection Issues**:
- Verify DATABASE_URL format
- Check database allows external connections
- Ensure SSL mode is configured correctly

**Static Files Not Loading**:
- Check `static/` folder structure
- Verify CSS/JS file paths in templates

**Import Errors**:
- Ensure all dependencies are in requirements.txt
- Check Python version compatibility

## Monitoring

- Use Vercel's built-in analytics
- Monitor database performance through your database provider
- Set up error logging (consider Sentry)

## Costs

**Vercel**: Free tier includes:
- 100GB bandwidth
- 10,000 monthly function invocations
- 1 concurrent build

**Database**: 
- Neon: Free tier with 10GB storage
- Supabase: Free tier with 500MB database
- Railway: $5/month for PostgreSQL

## Support

For issues specific to this deployment:
1. Check Vercel function logs
2. Verify environment variables
3. Test database connectivity
4. Review this deployment guide
