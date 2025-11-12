# SendGrid Setup Guide for OTP Email

## Step 1: Create SendGrid Account
1. Go to https://sendgrid.com/
2. Click "Start for Free"
3. Sign up (Free tier: 100 emails/day)

## Step 2: Verify Sender Email
1. Login to SendGrid Dashboard
2. Go to **Settings** → **Sender Authentication**
3. Click **Verify a Single Sender**
4. Enter your email: `techstartupts@gmail.com`
5. Fill the form and submit
6. Check your email and click verification link

## Step 3: Create API Key
1. Go to **Settings** → **API Keys**
2. Click **Create API Key**
3. Name: `EduConnect OTP`
4. Permissions: **Full Access** (or Mail Send only)
5. Click **Create & View**
6. **COPY THE API KEY** (you won't see it again!)

## Step 4: Update Environment Variables
Add to your `.env` file:
```
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SENDGRID_FROM_EMAIL=techstartupts@gmail.com
```

## Step 5: Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 6: Test Locally
```bash
uvicorn main:app --reload
```

## Step 7: Deploy to Render
1. Go to Render Dashboard
2. Select your service
3. Go to **Environment** tab
4. Add environment variables:
   - `SENDGRID_API_KEY` = your_api_key
   - `SENDGRID_FROM_EMAIL` = techstartupts@gmail.com
5. Save and redeploy

## Troubleshooting

### Error: "SENDGRID_API_KEY not configured"
- Make sure you added the API key to `.env` (local) or Render environment variables

### Error: "The from email does not match a verified Sender Identity"
- You must verify your sender email in SendGrid dashboard first
- Use the exact same email in `SENDGRID_FROM_EMAIL`

### Free Tier Limits
- 100 emails per day
- Enough for testing and small projects
- Upgrade if you need more

## Testing OTP Flow
1. Go to your login page
2. Enter email and request OTP
3. Check email inbox (and spam folder)
4. Enter OTP to verify

## Benefits over SMTP
✅ Works on Render free tier
✅ Faster delivery
✅ Better deliverability
✅ No port blocking issues
✅ Email analytics dashboard
