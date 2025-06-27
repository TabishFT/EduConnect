from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from imagekitio import ImageKit
import base64
from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
import io
from io import BytesIO
import requests
from pydantic import BaseModel, EmailStr
from typing import Optional, Literal, List
from pymongo import MongoClient, ASCENDING
import certifi
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import re
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.linkedin import LinkedInSSO
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse, JSONResponse
from dotenv import load_dotenv
from functools import wraps
from fastapi.templating import Jinja2Templates
from uuid import uuid4
import json
templates = Jinja2Templates(directory="templates")
# Load environment variables
load_dotenv()

# Determine if running in production
IS_PRODUCTION = os.getenv("APP_ENV", "development") == "production"

# Configuration settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# MongoDB setup with connection pooling
client = MongoClient(
    os.getenv("MONGODB_URL"),
    tlsCAFile=certifi.where(),
    maxPoolSize=50,
    waitQueueTimeoutMS=2000,
    connectTimeoutMS=2000,
    socketTimeoutMS=2000
)
db = client["startup_intern_db"]
users_collection = db["users"]

# Create indexes for better query performance
users_collection.create_index([("email", ASCENDING)], unique=True)
users_collection.create_index([("role", ASCENDING)])

# Security contexts
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI app setup
app = FastAPI()
FIREBASE_URL = os.getenv("FIREBASE_INTERN_DATABASE")
STARTUP_FIREBASE_URL = os.getenv("FIREBASE_STARTUP_DATABASE")
POSTS_FIREBASE_URL = os.getenv("FIREBASE_POSTS_DATABASE")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://internweb.onrender.com", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files with caching
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

# OAuth configurations
google_sso = GoogleSSO(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/google/callback",
    allow_insecure_http=False,
    scope=["openid", "email", "profile"] # Explicitly add default scopes
)

github_sso = GithubSSO(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/github/callback",
    allow_insecure_http=False,
)

linkedin_sso = LinkedInSSO(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/linkedin/callback",
    allow_insecure_http=False,
)

# --------------------- Models ---------------------

class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str
    created_at: datetime
    is_active: bool = True
    auth_provider: str = "email"
    role: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class RoleSelection(BaseModel):
    role: Literal["intern", "startup"]

# --------------------- Helper Functions ---------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    user = users_collection.find_one(
        {"email": email},
        {"_id": 0}
    )
    return User(**user) if user else None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print("\n--- Attempting to get current user ---")
    token = request.cookies.get("access_token")
    source = "cookie"
    if not token:
        print("Token not found in cookies.")
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            source = "header"
            print("Token found in Authorization header.")
        else:
            print("Token not found in Authorization header.")
            token = request.query_params.get("access_token")
            if token:
                source = "query_param"
                print("Token found in query parameters.")
            else:
                print("Token not found in cookies, headers, or query params. Raising 401.")
                raise credentials_exception
    else:
        print(f"Token found in: {source}")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        print("Decoded JWT payload:", payload)
        if email is None:
            print("Email (sub) not found in token payload. Raising 401.")
            raise credentials_exception
        print(f"Token decoded successfully. Email (sub): {email}")
    except JWTError as e:
        print(f"JWTError decoding token: {e}. Raising 401.")
        raise credentials_exception

    user = get_user(email)
    if user is None:
        print(f"User with email '{email}' not found in database. Raising 401.")
        raise credentials_exception

    print(f"User '{email}' found and authenticated successfully.")
    return user

# --------------------- Routes ---------------------

@app.get("/", include_in_schema=True)
@app.head("/", include_in_schema=True)
async def read_index(request: Request):
    return templates.TemplateResponse("getstarted.html", {"request": request})

@app.get("/login", include_in_schema=True)
@app.head("/login", include_in_schema=True)
async def login_page(request: Request):
    try:
        current_user = await get_current_user(request)
        if current_user and current_user.role:
            if current_user.role == "intern":
                return RedirectResponse(url="/interns/home", status_code=303)
            elif current_user.role == "startup":
                return RedirectResponse(url="/startups/home", status_code=303)
        # If no role or not authenticated, show login
        return templates.TemplateResponse("index.html", {"request": request})
    except HTTPException as e:
        # If unauthenticated, show login
        if e.status_code == 401:
            return templates.TemplateResponse("index.html", {"request": request})
        raise e

@app.get("/select_role", include_in_schema=True)
@app.head("/select_role", include_in_schema=True)
async def select_role_page(request: Request):
    try:
        current_user = await get_current_user(request)
        if current_user.role:
            # Redirect based on role
            if current_user.role == "intern":
                return RedirectResponse(url="/interns/home", status_code=303)
            elif current_user.role == "startup":
                return RedirectResponse(url="/startups/home", status_code=303)
            else:
                return RedirectResponse(url="/home", status_code=303)
        return templates.TemplateResponse("select_role.html", {"request": request})
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e
    except Exception as e:
        print(f"Error in select_role: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error on role selection")


@app.post("/api/set_role")
async def set_role(request: Request):
    try:
        current_user = await get_current_user(request)
        data = await request.json()
        
        # MongoDB update
        users_collection.update_one(
            {"email": current_user.email},
            {"$set": {"role": data.get("role")}}
        )
        return JSONResponse({"status": "Role updated successfully"})
    
    except Exception as e:
        print(f"Role update error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/intern_profile")
async def save_intern_profile(
    profile: dict,
    current_user: User = Depends(get_current_user)
):
    try:
        # Ensure email exists
        if not current_user.email:
            raise HTTPException(status_code=400, detail="Email missing for current user")

        # Log email for debugging

        print("Saving profile for user:", current_user.email)

        # Sanitize email for Firebase path
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)

        # Convert empty strings to null
        for key, val in profile.items():
            if val == "":
                profile[key] = None

        firebase_path = f"{FIREBASE_URL.rstrip('/')}/interns/{safe_email}.json"
        print("Raw email:", current_user.email)
        print("Sanitized email:", safe_email)
        resp = requests.put(firebase_path, json=profile)

        if resp.status_code in (200, 204):
            return JSONResponse({"status": "profile saved"})
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Firebase error: {resp.status_code} {resp.text}"
            )
    except Exception as e:
        print("Profile save error:", str(e))
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/startup_profile")
async def save_startup_profile(
    profile: dict,
    current_user: User = Depends(get_current_user)
):
    try:
        # Ensure email exists
        if not current_user.email:
            raise HTTPException(status_code=400, detail="Email missing for current user")

        print("Saving STARTUP profile for user:", current_user.email)

        # Sanitize email for Firebase path
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)

        # Convert empty strings to null
        for key, val in profile.items():
            if val == "":
                profile[key] = None

        # Use the same path format as intern endpoint
        firebase_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups/{safe_email}.json"
        print("Firebase path:", firebase_path)
        print("Profile data:", profile)

        resp = requests.put(firebase_path, json=profile)
        print("Firebase response:", resp.status_code, resp.text)

        if resp.status_code in (200, 204):
            return JSONResponse({"status": "profile saved"})
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Firebase error: {resp.status_code} {resp.text}"
            )
    except Exception as e:
        print("STARTUP Profile save error:", str(e))
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))






@app.get("/intern_profile")
async def intern_profile_page(request: Request):
    try:
        current_user = await get_current_user(request)
        # Allow access if role is being set via localStorage
        if current_user.role not in ["intern", None]:
            raise HTTPException(status_code=403, detail="Access denied")
        return templates.TemplateResponse("intern_profile.html", {"request": request})
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e

@app.get("/startup_profile")
async def startup_profile_page(request: Request):
    try:
        current_user = await get_current_user(request)
        # Allow access if role is being set via localStorage
        if current_user.role not in ["startup", None]:
            raise HTTPException(status_code=403, detail="Access denied")
        return templates.TemplateResponse("startup_profile.html", {"request": request})
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e

@app.get("/home")
async def home_page(request: Request):
    try:
        current_user = await get_current_user(request)
        if not current_user.role:
            return RedirectResponse(url="/select_role", status_code=303)

        if current_user.role == "intern":
            return RedirectResponse(url="/interns/home", status_code=303)
        elif current_user.role == "startup":
            return RedirectResponse(url="/startups/home", status_code=303)
        else:
            return RedirectResponse(url="/select_role", status_code=303)
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e

@app.get("/getstarted")
async def getstarted_page_redirect(request: Request):
    # This route used to show the page after login.
    # Now, the initial page is getstarted served at '/', so redirect any calls here.
    return RedirectResponse(url="/", status_code=303)
    # try:
    #     current_user = await get_current_user(request)
    #     if current_user.role:
    #         return RedirectResponse(url="/home", status_code=303)
    #     # If authenticated but no role, they should be selecting a role
    #     return RedirectResponse(url="/select_role", status_code=303)
    # except HTTPException as e:
    #     if e.status_code == 401:
    #          # If not authenticated, they should start at the beginning
    #         return RedirectResponse(url="/", status_code=303)
    #     raise e

@app.get("/preview")
async def intern_preview_page(request: Request):
    return templates.TemplateResponse("preview.html", {"request": request})

@app.get("/preview2")
async def startup_preview_page(request: Request):
    return templates.TemplateResponse("preview2.html", {"request": request})


@app.get("/startups/home")
async def startup_home(request: Request, current_user: User = Depends(get_current_user)):
    # Check if user is a startup
    if current_user.role != "startup":
        raise HTTPException(status_code=403, detail="Access denied. Only startups can access this page.")
    
    return templates.TemplateResponse("startups/home.html", {"request": request})


# --------------------- Authentication Routes ---------------------

@app.post("/signup")
async def signup(user: UserCreate, response: Response):
    if get_user(email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_dict = {
        "email": user.email,
        "name": user.name,
        "password": get_password_hash(user.password),
        "id": str(datetime.utcnow().timestamp()),
        "created_at": datetime.utcnow(),
        "auth_provider": "email",
        "role": None
    }

    users_collection.insert_one(user_dict)
    
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite='Lax',
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        
    )
    
    return {"redirect_url": "/select_role"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user_dict = users_collection.find_one(
        {"email": form_data.username},
        {"password": 1, "auth_provider": 1, "role": 1, "_id": 0}
    )
    
    if not user_dict or user_dict["auth_provider"] != "email" or \
       not verify_password(form_data.password, user_dict.get("password", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite='Lax',
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    redirect_url = "/home" if user_dict.get("role") else "/select_role"
    return {"redirect_url": redirect_url}

# OAuth handlers
async def handle_oauth_callback(request: Request, user_info, provider: str):
    try:
        # Use find_one and project only necessary fields
        db_user_data = users_collection.find_one(
            {"email": user_info.email},
            {"_id": 0, "role": 1} # Only need role to decide redirect
        )

        if not db_user_data:
            user_data = {
                "email": user_info.email,
                "name": user_info.display_name,
                "id": str(datetime.utcnow().timestamp()),
                "created_at": datetime.utcnow(),
                "auth_provider": provider,
                "role": None
            }
            users_collection.insert_one(user_data)
            # New user, redirect to select role
            redirect_url = "/select_role"
        else:
            # Existing user - determine redirect based on role
            role = db_user_data.get("role")
            if role == "intern":
                redirect_url = "/interns/home"
            elif role == "startup":
                redirect_url = "/startups/home"
            else:
                redirect_url = "/select_role"

        access_token = create_access_token(
            data={"sub": user_info.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Return both redirect URL and token
        return {"redirect_url": redirect_url, "access_token": access_token}
    except Exception as e:
        print(f"OAuth callback error for {provider}: {str(e)}") # Add provider context
        raise HTTPException(
            status_code=500,
            detail=f"Authentication failed: {str(e)}"
        )

@app.get("/auth/google/login")
async def google_login():
    return await google_sso.get_login_redirect()

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        user = await google_sso.verify_and_process(request)
        result = await handle_oauth_callback(request, user, "google")
        
        redirect_url = result['redirect_url']
        access_token = result['access_token']
        
        response = RedirectResponse(url=redirect_url, status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite='Lax',
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        return response
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        print(f"Google callback error: {str(e)}")
        return RedirectResponse(url="/login", status_code=303)

@app.get("/auth/github/login")
async def github_login():
    return await github_sso.get_login_redirect()

@app.get("/auth/github/callback")
async def github_callback(request: Request):
    try:
        user = await github_sso.verify_and_process(request)
        result = await handle_oauth_callback(request, user, "github")
        
        redirect_url = result['redirect_url']
        access_token = result['access_token']
        
        response = RedirectResponse(url=redirect_url, status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite='Lax',
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        return response
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        print(f"Github callback error: {str(e)}")
        return RedirectResponse(url="/login", status_code=303)

@app.get("/auth/linkedin/login")
async def linkedin_login():
    return await linkedin_sso.get_login_redirect()

@app.get("/auth/linkedin/callback")
async def linkedin_callback(request: Request):
    try:
        user = await linkedin_sso.verify_and_process(request)
        result = await handle_oauth_callback(request, user, "linkedin")
        
        redirect_url = result['redirect_url']
        access_token = result['access_token']
        
        response = RedirectResponse(url=redirect_url, status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite='Lax',
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        return response
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        print(f"LinkedIn callback error: {str(e)}")
        return RedirectResponse(url="/login", status_code=303)




#imagekit:
imagekit = ImageKit(
    private_key=os.getenv("IMAGEKIT_PRIVATE_KEY"),
    public_key=os.getenv("IMAGEKIT_PUBLIC_KEY"),
    url_endpoint="https://ik.imagekit.io/iupyun2hd"
)

posts_imagekit = ImageKit(
    private_key=os.getenv("POSTS_IMAGEKIT_PRIVATE_KEY"),
    public_key=os.getenv("POSTS_IMAGEKIT_PUBLIC_KEY"),
    url_endpoint="https://ik.imagekit.io/educonnect"
)






@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: object = Depends(get_current_user)
):
    try:
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
        contents = await file.read()

        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large")

        # Create a safe filename from user's email
        raw_email = current_user.email
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", raw_email)

        if not file.filename or '.' not in file.filename:
            raise HTTPException(status_code=400, detail="Invalid file name")

        file_ext = file.filename.split(".")[-1].lower()

        if file_ext in ["jpg", "jpeg", "png"]:
            file_type = "image"
            final_filename = f"{safe_email}_profile.{file_ext}"
            upload_data = base64.b64encode(contents).decode("utf-8")  # ✅ Now image will upload as base64 too
        elif file_ext in ["pdf", "doc", "docx"]:
            file_type = "pdf"
            final_filename = f"{safe_email}_resume.{file_ext}"
            upload_data = base64.b64encode(contents).decode("utf-8")  # Already correct
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")


        # Set upload options
        upload_options = UploadFileRequestOptions(
            folder="/uploads/",
            use_unique_file_name=False,
            overwrite_file=True,
            is_private_file=False,
            tags=[file_type, "user_upload"]
        )

        # Upload to ImageKit
        result = imagekit.upload(
            file=upload_data,
            file_name=final_filename,
            options=upload_options
        )

        if result and hasattr(result, 'url') and result.url:
            return {
                "success": True,
                "url": result.url,
                "name": final_filename,
                "file_type": file_type,
                "size": len(contents)
            }
        else:
            error_msg = "ImageKit upload failed"
            if hasattr(result, 'error'):
                error_msg = f"ImageKit error: {result.error}"
            elif hasattr(result, 'response_metadata'):
                error_msg = f"Upload failed: {result.response_metadata}"
            return JSONResponse(content={"success": False, "error": error_msg}, status_code=500)

    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(content={"success": False, "error": f"Upload failed: {str(e)}"}, status_code=500)



@app.get("/get_intern_profiles")
@app.get("/get_intern_profiles/")  # Handle both with and without trailing slash
async def get_intern_profiles(current_user: User = Depends(get_current_user)):
    """
    Get all intern profiles from Firebase - accessible only to startups
    """
    try:
        # Only allow startups to access intern profiles
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only startups can view intern profiles."
            )
        
        # Construct Firebase URL
        if not FIREBASE_URL:
            raise HTTPException(
                status_code=500,
                detail="Firebase URL not configured"
            )
            
        firebase_path = f"{FIREBASE_URL.rstrip('/')}/interns.json"
        print(f"🔥 Fetching from Firebase: {firebase_path}")
        
        # Make request to Firebase
        try:
            response = requests.get(firebase_path, timeout=10)
            print(f"📡 Firebase response status: {response.status_code}")
            
        except requests.exceptions.Timeout:
            raise HTTPException(
                status_code=504,
                detail="Firebase request timed out"
            )
        except requests.exceptions.ConnectionError:
            raise HTTPException(
                status_code=503,
                detail="Cannot connect to Firebase"
            )
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=500,
                detail=f"Firebase request failed: {str(e)}"
            )
        
        # Check Firebase response
        if response.status_code != 200:
            print(f"❌ Firebase error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=500,
                detail=f"Firebase returned error: {response.status_code}"
            )
        
        # Parse Firebase data
        try:
            profiles_data = response.json()
        except ValueError as e:
            raise HTTPException(
                status_code=500,
                detail="Invalid JSON response from Firebase"
            )
        
        # Handle empty or null response
        if not profiles_data:
            print("📝 No profiles found in Firebase")
            return {
                "success": True,
                "profiles": [],
                "total_count": 0,
                "message": "No intern profiles found"
            }
        
        # Convert Firebase object to list
        profiles_list = []
        for email_key, profile_data in profiles_data.items():
            if profile_data and isinstance(profile_data, dict):
                # Clean and validate profile data
                clean_profile = {
                    'email_key': email_key,
                    'fullName': profile_data.get('fullName', 'Anonymous'),
                    'headline': profile_data.get('headline', ''),
                    'bio': profile_data.get('bio', ''),
                    'location': profile_data.get('location', ''),
                    'profilePicture': profile_data.get('profilePicture', ''),
                    'resumeUrl': profile_data.get('resumeUrl', ''),
                    'skills': [],
                    'education': profile_data.get('education', ''),
                    'linkedin': profile_data.get('linkedin', ''),
                    'github': profile_data.get('github', ''),
                    'website': profile_data.get('website', ''),
                    'field' : profile_data.get('field', ''),
                    'industry' : profile_data.get('industry', ''),
                    'phone' : profile_data.get('phone', ''),
                    'profession' : profile_data.get('profession', ''),
                    'twitter' : profile_data.get('twitter', '')
                }
                
                # Handle skills - ensure it's always a list
                raw_skills = profile_data.get('skills', '')
                if isinstance(raw_skills, str):
                    if raw_skills.strip():
                        clean_profile['skills'] = [
                            skill.strip() 
                            for skill in raw_skills.split(',') 
                            if skill.strip()
                        ]
                elif isinstance(raw_skills, list):
                    clean_profile['skills'] = [
                        str(skill).strip() 
                        for skill in raw_skills 
                        if skill and str(skill).strip()
                    ]
                
                profiles_list.append(clean_profile)
        
        print(f"✅ Successfully processed {len(profiles_list)} intern profiles")
        
        return {
            "success": True,
            "profiles": profiles_list,
            "total_count": len(profiles_list)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Unexpected error in get_intern_profiles: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/startups/post")
async def startup_post_page(request: Request, current_user: User = Depends(get_current_user)):
    """
    Post creation page - accessible only to authenticated startups
    """
    try:
        # Check if user is authenticated startup
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only startups can create posts."
            )
        
        return templates.TemplateResponse("startups/post.html", {"request": request})
    
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e


@app.post("/api/create_post")
async def create_post(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Create a new post - accessible only to authenticated startups
    """
    try:
        # Check if user is authenticated startup
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only startups can create posts."
            )
        
        # Get form data
        form_data = await request.form()
        
        # Extract post data
        post_data = {
            "name": form_data.get("name", "").strip(),
            "tagline": form_data.get("tagline", "").strip(),
            "title": form_data.get("title", "").strip(),
            "skills": form_data.get("skills", "").strip(),
            "description": form_data.get("description", "").strip()
        }
        
        # Basic validation
        if not post_data["name"] or not post_data["title"]:
            raise HTTPException(
                status_code=400,
                detail="Startup name and job title are required"
            )
        
        # Handle image upload if present
        image_url = ""
        image_file = form_data.get("image")
        
        if image_file and hasattr(image_file, 'filename') and image_file.filename:
            try:
                # Read image file
                image_contents = await image_file.read()
                
                # Validate file size (max 2MB as per frontend)
                MAX_IMAGE_SIZE = 4 * 1024 * 1024  # 2MB
                if len(image_contents) > MAX_IMAGE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Image file too large. Maximum size is 2MB."
                    )
                
                # Validate file type
                if not image_file.content_type.startswith('image/'):
                    raise HTTPException(
                        status_code=400,
                        detail="Only image files are allowed"
                    )
                
                # Create unique filename
                file_extension = image_file.filename.split('.')[-1].lower()
                post_id = str(uuid4())
                safe_startup_name = re.sub(r"[^A-Za-z0-9]", "_", post_data["name"])
                unique_filename = f"post_{safe_startup_name}_{post_id}.{file_extension}"
                
                # Encode image for ImageKit
                image_base64 = base64.b64encode(image_contents).decode("utf-8")
                
                # Upload to posts_imagekit
                upload_options = UploadFileRequestOptions(
                    folder="/posts/",
                    use_unique_file_name=False,
                    overwrite_file=False,
                    is_private_file=False,
                    tags=["post", "startup", safe_startup_name]
                )
                
                result = posts_imagekit.upload(
                    file=image_base64,
                    file_name=unique_filename,
                    options=upload_options
                )
                
                if result and hasattr(result, 'url') and result.url:
                    image_url = result.url
                    print(f"✅ Image uploaded successfully: {image_url}")
                else:
                    print("❌ ImageKit upload failed")
                    raise HTTPException(
                        status_code=500,
                        detail="Failed to upload image"
                    )
                    
            except HTTPException:
                raise
            except Exception as e:
                print(f"❌ Image upload error: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Image upload failed: {str(e)}"
                )
        
        # Create post object with all details
        post_object = {
            "id": str(uuid4()),
            "startup_name": post_data["name"],
            "tagline": post_data["tagline"],
            "job_title": post_data["title"],
            "skills": post_data["skills"],
            "description": post_data["description"],
            "image_url": image_url,
            "created_at": datetime.utcnow().isoformat(),
            "status": "published"
        }
        
        # Store in Firebase (POSTS_FIREBASE_URL)
        try:
            if not POSTS_FIREBASE_URL:
                raise HTTPException(
                    status_code=500,
                    detail="Posts Firebase URL not configured"
                )
            
            # Create unique path for the post
            firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_object['id']}.json"
            print(f"🔥 Storing post in Firebase: {firebase_path}")
            
            response = requests.put(firebase_path, json=post_object, timeout=10)
            
            if response.status_code in (200, 204):
                print("✅ Post stored successfully in Firebase")
                return JSONResponse({
                    "success": True,
                    "message": "Post published successfully!",
                    "post_id": post_object["id"],
                    "redirect_url": "/startups/home"
                })
            else:
                print(f"❌ Firebase storage failed: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to store post in database"
                )
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Firebase request error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Database connection error"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Unexpected error in create_post: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/api/view_post/{post_id}")
async def view_post(
    post_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    View a specific post by ID
    """
    try:
        if not POSTS_FIREBASE_URL:
            raise HTTPException(
                status_code=500,
                detail="Posts Firebase URL not configured"
            )
        
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code == 200:
            post_data = response.json()
            if post_data:
                return JSONResponse({
                    "success": True,
                    "post": post_data
                })
            else:
                raise HTTPException(status_code=404, detail="Post not found")
        else:
            raise HTTPException(status_code=404, detail="Post not found")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error viewing post: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve post"
        )


@app.get("/api/auth/check")
async def check_authentication(request: Request):
    """
    Check if user is authenticated and return user info
    """
    try:
        current_user = await get_current_user(request)
        
        return JSONResponse({
            "authenticated": True,
            "user": {
                "email": current_user.email,
                "name": current_user.name,
                "role": current_user.role,
                "auth_provider": current_user.auth_provider,
                "created_at": current_user.created_at.isoformat() if current_user.created_at else None
            }
        })
        
    except HTTPException as e:
        if e.status_code == 401:
            return JSONResponse({
                "authenticated": False,
                "detail": "Not authenticated"
            }, status_code=401)
        raise e
    except Exception as e:
        print(f"Authentication check error: {str(e)}")
        return JSONResponse({
            "authenticated": False,
            "detail": "Authentication check failed"
        }, status_code=500)


@app.get("/api/get_all_posts")
async def get_all_posts(
    current_user: User = Depends(get_current_user),
    limit: int = 5,  # Number of posts to return per page
    start_after: Optional[str] = None
):
    """
    Get all posts from Firebase - accessible to authenticated users
    """
    try:
        # Check if user is authenticated
        if not current_user:
            raise HTTPException(
                status_code=401, 
                detail="Authentication required"
            )
        
        # Construct Firebase URL
        if not POSTS_FIREBASE_URL:
            raise HTTPException(
                status_code=500,
                detail="Posts Firebase URL not configured"
            ) [cite: 56]
            
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts.json"
        fetch_limit = limit + 1
        params = {
        'orderBy': '"$key"',  # Order by the unique key of each post
        'limitToFirst': fetch_limit
    }

        # If start_after is provided, use it as the starting point for the query
        if start_after:
            # The key must be in quotes for the Firebase REST API
            params['startAt'] = f'"{start_after}"'
        print(f"🔥 Fetching posts from Firebase: {firebase_path}")
        
        # Make request to Firebase
        try:
            response = requests.get(firebase_path, timeout=10)
            print(f"📡 Firebase response status: {response.status_code}") [cite: 57]
            
        except requests.exceptions.Timeout:
            raise HTTPException(
                status_code=504,
                detail="Firebase request timed out"
            )
        except requests.exceptions.ConnectionError:
            raise HTTPException(
                status_code=503,
                detail="Cannot connect to Firebase"
            )
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=500,
                detail=f"Firebase request failed: {str(e)}"
            )
        
        # Check Firebase response
        if response.status_code != 200:
            print(f"❌ Firebase error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=500,
                detail=f"Firebase returned error: {response.status_code}"
            )
        
        # Parse Firebase data
        try:
            posts_data = response.json()
        except ValueError as e:
            raise HTTPException(
                status_code=500,
                detail="Invalid JSON response from Firebase"
            ) [cite: 62]
        
        # Handle empty or null response
        if not posts_data:
            print("📝 No posts found in Firebase")
            return {"success": True, "posts": [], "next_cursor": None}
        
        # Convert Firebase object to list
        posts_list = []
        if start_after and start_after in posts_data:
            # Create an iterator and skip the first element
            data_iterator = iter(posts_data.items())
            next(data_iterator) 
            posts_to_process = dict(data_iterator)
        else:
            posts_to_process = posts_data


        for post_id, post_data in posts_data.items():
            if post_data and isinstance(post_data, dict):
                # Clean and validate post data
                clean_post = {
                    'id': post_data.get('id', post_id),
                    'startup_name': post_data.get('startup_name', 'Unknown Startup'),
                    'tagline': post_data.get('tagline', ''),
                    'job_title': post_data.get('job_title', 'Position Available'),
                    'skills': post_data.get('skills', ''),
                    'description': post_data.get('description', ''),
                    'image_url': post_data.get('image_url', ''),
                    'created_at': post_data.get('created_at', ''),
                    'status': post_data.get('status', 'published'),
                    'startup_profile': post_data.get('startup_profile', {}),
                    'location': post_data.get('location', ''),
                    'duration': post_data.get('duration', ''),
                    'stipend': post_data.get('stipend', ''),
                    'application_count': post_data.get('application_count', 0),
                    'likes_count': post_data.get('likes_count', 0),
                    'shares_count': post_data.get('shares_count', 0)
                }
                
                # Only include published posts
                if clean_post['status'] == 'published':
                    posts_list.append(clean_post)

        next_cursor = None
        if len(posts_list) > limit:
            # We fetched one extra item, so there are more posts.
            # The key of the last item in our intended batch is the next cursor.
            # Pop the extra item off the list.
            last_item = posts_list.pop(limit) 
            next_cursor = last_item['id']
        
        # Sort posts by creation date (newest first)
        posts_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        print(f"✅ Successfully processed {len(posts_list)} posts")
        
        return {
            "success": True,
            "posts": posts_list,
            "total_count": len(posts_list),
            "next_cursor": next_cursor
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Unexpected error in get_all_posts: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail="Internal server error while fetching posts"
        )


@app.post("/api/like_post/{post_id}")
async def like_post(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Like/Unlike a post
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get current post data
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail="Post not found")
        
        post_data = response.json()
        if not post_data:
            raise HTTPException(status_code=404, detail="Post not found")
        
        # Update likes count
        current_likes = post_data.get('likes_count', 0)
        updated_likes = current_likes + 1
        
        # Update Firebase
        update_data = {'likes_count': updated_likes}
        update_response = requests.patch(firebase_path, json=update_data, timeout=10)
        
        if update_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to update likes")
        
        return {
            "success": True,
            "message": "Post liked successfully",
            "likes_count": updated_likes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error liking post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/share_post/{post_id}")
async def share_post(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Share a post (increment share count)
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get current post data
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail="Post not found")
        
        post_data = response.json()
        if not post_data:
            raise HTTPException(status_code=404, detail="Post not found")
        
        # Update shares count
        current_shares = post_data.get('shares_count', 0)
        updated_shares = current_shares + 1
        
        # Update Firebase
        update_data = {'shares_count': updated_shares}
        update_response = requests.patch(firebase_path, json=update_data, timeout=10)
        
        if update_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to update shares")
        
        return {
            "success": True,
            "message": "Post shared successfully",
            "shares_count": updated_shares,
            "share_url": f"{request.base_url}post/{post_id}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sharing post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/interns/home")
async def interns_home_page(request: Request, current_user: User = Depends(get_current_user)):
    """
    Serve the interns home page
    """
    try:
        if not current_user:
            # Redirect to login if not authenticated
            return RedirectResponse(url="/login", status_code=302)
        
        # Return the HTML template (assuming you have the HTML file in templates directory)
        return templates.TemplateResponse("interns/home.html", {
            "request": request,
            "user": current_user
        })
        
    except Exception as e:
        print(f"Error serving interns home page: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/message_startup")
async def message_startup(
    startup_name: str = Form(...),
    message: str = Form(...),
    current_user: User = Depends(get_current_user)
):
    """
    Send message to startup
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Create message data
        message_data = {
            'id': str(uuid.uuid4()),
            'from_user': current_user.email,
            'from_name': getattr(current_user, 'name', current_user.email),
            'to_startup': startup_name,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'status': 'sent'
        }
        
        # Save to Firebase messages collection
        messages_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/messages/{message_data['id']}.json"
        response = requests.put(messages_path, json=message_data, timeout=10)
        
        if response.status_code not in [200, 201]:
            raise HTTPException(status_code=500, detail="Failed to send message")
        
        return {
            "success": True,
            "message": f"Message sent to {startup_name} successfully",
            "message_id": message_data['id']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        proxy_headers=True,
        forwarded_allow_ips="*"
    )