from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File, Form, Query
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
from typing import Optional, Literal, List, Dict, Any
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
import asyncio
import socketio
from threading import Timer
import threading
from collections import defaultdict
import time
from uuid import uuid4


templates = Jinja2Templates(directory="templates")
# FastAPI app setup
app = FastAPI()


def cleanup_old_messages():
    """Remove messages older than 24 hours"""
    with message_lock:
        current_time = time.time()
        global chat_messages
        chat_messages = [msg for msg in chat_messages if current_time - msg['timestamp'] < 86400]  # 24 hours
    
    # Schedule next cleanup
    Timer(3600, cleanup_old_messages).start()  # Run every hour

# Start the cleanup timer
cleanup_old_messages()

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

# Socket.IO setup
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=["https://myeduconnect.onrender.com", "http://localhost:8000", "http://127.0.0.1:8000"],
    logger=True,
    engineio_logger=True
)
# Combine FastAPI and Socket.IO
socket_app = socketio.ASGIApp(sio, app)
FIREBASE_URL = os.getenv("FIREBASE_INTERN_DATABASE")
STARTUP_FIREBASE_URL = os.getenv("FIREBASE_STARTUP_DATABASE")
POSTS_FIREBASE_URL = os.getenv("FIREBASE_POSTS_DATABASE")

# In-memory chat storage with automatic cleanup
chat_messages = []  # List of all messages with timestamps
user_connections = {}  # {user_email: [socket_ids]}
socket_users = {}  # {socket_id: user_email}
message_lock = threading.Lock()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myeduconnect.onrender.com", "http://localhost:8000", "http://127.0.0.1:8000"],
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
    redirect_uri="https://myeduconnect.onrender.com/auth/google/callback",
    allow_insecure_http=False,
    scope=["openid", "email", "profile"] # Explicitly add default scopes
)

github_sso = GithubSSO(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri="https://myeduconnect.onrender.com/auth/github/callback",
    allow_insecure_http=False,
)

linkedin_sso = LinkedInSSO(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    redirect_uri="https://myeduconnect.onrender.com/auth/linkedin/callback",
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

@app.get("/intern/profile/view")
async def view_intern_profile_page(request: Request, current_user: User = Depends(get_current_user)):
    """
    View individual intern profile page - accessible only to authenticated startups
    """
    try:
        # Check if user is authenticated startup
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only startups can view intern profiles."
            )
        
        return templates.TemplateResponse("startups/view_intern_profile.html", {"request": request})
    
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e


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

#---------------------------------------
posts_cache = {
    'data': None,
    'timestamp': None,
    'lock': asyncio.Lock()
}

profiles_cache = {
    'data': None,
    'timestamp': None,
    'lock': asyncio.Lock()
}

CACHE_DURATION = timedelta(minutes=10)  # ⏰ 10 MINUTES CACHE
#---------------------------------------

@app.get("/get_intern_profiles")
@app.get("/get_intern_profiles/")
async def get_intern_profiles(
    current_user: User = Depends(get_current_user),
    limit: int = Query(5, ge=1, le=20, description="Profiles per page"),
    start_after: Optional[str] = Query(None, description="Cursor for pagination"),
    skills: Optional[str] = Query(None, description="Comma-separated skills to filter by")
):
    """
    Get intern profiles with 10 MINUTE SMART CACHING - Perfect balance!
    """
    try:
        # Check authorization
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403,
                detail="Access denied. Only startups can view intern profiles."
            )
        
        # 🎯 SMART CACHE CHECK (10 MINUTES)
        async with profiles_cache['lock']:
            cache_valid = (
                profiles_cache['data'] is not None and 
                profiles_cache['timestamp'] is not None and
                datetime.utcnow() - profiles_cache['timestamp'] < CACHE_DURATION
            )
            
            if cache_valid:
                # ⚡ CACHE HIT - Instant response!
                profiles_data = profiles_cache['data']
                cache_status = "hit"
                print("✨ Profiles Cache HIT - Serving from memory (10 min cache)")
            else:
                # 🔥 CACHE MISS - Fetch from Firebase
                print("🔥 Profiles Cache MISS - Fetching from Firebase")
                cache_status = "miss"
                
                firebase_path = f"{FIREBASE_URL.rstrip('/')}/interns.json"
                
                try:
                    response = requests.get(firebase_path, timeout=10)
                    
                    if response.status_code == 200:
                        profiles_data = response.json()
                        # ✅ Update cache with fresh data
                        profiles_cache['data'] = profiles_data
                        profiles_cache['timestamp'] = datetime.utcnow()
                        print(f"✅ Profiles cache updated (valid for 10 minutes) with {len(profiles_data) if profiles_data else 0} items")
                    else:
                        # Use stale cache if available
                        if profiles_cache['data'] is not None:
                            profiles_data = profiles_cache['data']
                            cache_status = "stale"
                            print("⚠️ Using stale profiles cache due to Firebase error")
                        else:
                            raise HTTPException(status_code=500, detail="Firebase error")
                            
                except requests.exceptions.RequestException as e:
                    # Network error - use stale cache if available
                    if profiles_cache['data'] is not None:
                        profiles_data = profiles_cache['data']
                        cache_status = "stale"
                        print(f"⚠️ Using stale profiles cache due to network error: {str(e)}")
                    else:
                        raise HTTPException(status_code=503, detail="Service unavailable")
        
        # Handle empty data
        if not profiles_data:
            return {
                "success": True,
                "profiles": [],
                "returned_count": 0,
                "total_count": 0,
                "next_cursor": None,
                "has_more": False,
                "cache_status": cache_status
            }
        
        # Process profiles
        profiles_list = []
        for profile_id, profile_data in profiles_data.items():
            if profile_data and isinstance(profile_data, dict):
                profiles_list.append({
                    'id': profile_id,
                    'profilePicture': profile_data.get('profilePicture', ''),
                    'fullName': profile_data.get('fullName', 'Unknown'),
                    'email': profile_data.get('email', ''),
                    'skills': profile_data.get('skills', []),
                    'bio': profile_data.get('bio', ''),
                    'experience': profile_data.get('experience', ''),
                    'education': profile_data.get('education', ''),
                    'linkedin': profile_data.get('linkedin', ''),
                    'github': profile_data.get('github', ''),
                    'location': profile_data.get('location', ''),
                    'availability': profile_data.get('availability', ''),
                    'created_at': profile_data.get('created_at', ''),
                    'updated_at': profile_data.get('updated_at', ''),
                    'resumeUrl': profile_data.get('resumeUrl', ''),
                    'website': profile_data.get('website', ''),
                    'headline': profile_data.get('headline', ''),
                    'phone': profile_data.get('phone', ''),
                    'twitter': profile_data.get('twitter', ''),
                    'field': profile_data.get('field', ''),
                    'industry': profile_data.get('industry', ''),
                    'company': profile_data.get('company', ''),
                    'workExperience': profile_data.get('workExperience', '')
                })
        
        # Apply skill filtering
        filtered_profiles = []
        
        if skills:
            skill_filters = [s.strip().lower() for s in skills.split(',') if s.strip()]
            
            for profile in profiles_list:
                profile_skills = profile.get('skills', [])
                if not isinstance(profile_skills, list):
                    profile_skills = []
                
                profile_skills_lower = [skill.lower() for skill in profile_skills if skill]
                
                # Calculate match score
                matched_skills = 0
                for filter_skill in skill_filters:
                    if any(filter_skill in profile_skill for profile_skill in profile_skills_lower):
                        matched_skills += 1
                
                match_score = (matched_skills / len(skill_filters)) * 100 if skill_filters else 0
                
                if match_score > 0:
                    profile['match_score'] = match_score
                    profile['matched_skills_count'] = matched_skills
                    filtered_profiles.append(profile)
            
            # Sort by match score
            filtered_profiles.sort(key=lambda x: (
                -x.get('match_score', 0),
                -len(x.get('skills', [])),
                x.get('fullName', '').lower()
            ))
        else:
            # No filter - use all profiles sorted by name
            filtered_profiles = sorted(profiles_list, key=lambda x: x.get('fullName', '').lower())
        
        # Pagination logic
        start_index = 0
        if start_after:
            for i, profile in enumerate(filtered_profiles):
                if profile['id'] == start_after:
                    start_index = i + 1
                    break
        
        end_index = start_index + limit
        paginated_profiles = filtered_profiles[start_index:end_index]
        has_more = end_index < len(filtered_profiles)
        next_cursor = paginated_profiles[-1]['id'] if has_more and paginated_profiles else None
        
        # Clean up internal fields
        if not skills:
            for profile in paginated_profiles:
                profile.pop('match_score', None)
                profile.pop('matched_skills_count', None)
        
        return {
            "success": True,
            "profiles": paginated_profiles,
            "returned_count": len(paginated_profiles),
            "total_count": len(filtered_profiles),
            "total_available": len(profiles_list),
            "next_cursor": next_cursor,
            "has_more": has_more,
            "skills_applied": skills if skills else None,
            "cache_status": cache_status,
            "cache_age_seconds": int((datetime.utcnow() - profiles_cache['timestamp']).total_seconds()) if profiles_cache['timestamp'] else None,
            "cache_duration_minutes": 10
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Error in get_intern_profiles: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")



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
async def create_post(request: Request, current_user: User = Depends(get_current_user)):
    """
    Create a new post - accessible only to authenticated startups
    """
    try:
        # 1. Check if user is an authenticated startup
        if current_user.role != "startup":
            raise HTTPException(
                status_code=403,
                detail="Access denied. Only startups can create posts."
            )

        # 2. Get and validate form data
        form_data = await request.form()
        post_data = {
            "name": form_data.get("name", "").strip(),
            "tagline": form_data.get("tagline", "").strip(),
            "title": form_data.get("title", "").strip(),
            "skills": form_data.get("skills", "").strip(),
            "description": form_data.get("description", "").strip()
        }

        if not post_data["name"] or not post_data["title"]:
            raise HTTPException(
                status_code=400,
                detail="Startup name and job title are required"
            )

        # 3. Handle image upload if present
        image_url = ""
        image_file = form_data.get("image")
        if image_file and hasattr(image_file, 'filename') and image_file.filename:
            try:
                image_contents = await image_file.read()
                MAX_IMAGE_SIZE = 4 * 1024 * 1024  # 4MB
                if len(image_contents) > MAX_IMAGE_SIZE:
                    raise HTTPException(status_code=413, detail="Image file too large. Maximum size is 4MB.")
                if not image_file.content_type.startswith('image/'):
                    raise HTTPException(status_code=400, detail="Only image files are allowed.")

                file_extension = image_file.filename.split('.')[-1].lower()
                post_id = str(uuid4())
                safe_startup_name = re.sub(r"[^A-Za-z0-9]", "_", post_data["name"])
                unique_filename = f"post_{safe_startup_name}_{post_id}.{file_extension}"

                image_base64 = base64.b64encode(image_contents).decode("utf-8")
                
                upload_options = UploadFileRequestOptions(
                    folder="/posts/", use_unique_file_name=False, overwrite_file=False
                )
                result = posts_imagekit.upload(
                    file=image_base64, file_name=unique_filename, options=upload_options
                )
                image_url = result.url
                print(f"✅ Image uploaded successfully: {image_url}")

            except HTTPException:
                raise
            except Exception as e:
                print(f"❌ Image upload error: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

        # 4. Check/Update/Create Startup Profile in Firebase
        print(f"🔍 Checking/Updating startup profile for user: {current_user.email}")
        
        # ---> IMPROVEMENT: Use Firebase query to find the profile directly by email
        profile_query_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups.json"
        query_params = {'orderBy': '"contactEmail"', 'equalTo': f'"{current_user.email}"'}
        
        try:
            response = requests.get(profile_query_path, params=query_params, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            
            existing_profiles = response.json() or {}
            
            if existing_profiles:
                # Profile exists, update it if needed
                profile_id = next(iter(existing_profiles)) # Get the unique ID of the profile
                profile_data = existing_profiles[profile_id]
                print(f"✅ Found existing profile for {current_user.email} with ID: {profile_id}")
                
                if profile_data.get('startupName', '') != post_data["name"]:
                    print(f"📝 Updating startup name from '{profile_data.get('startupName', '')}' to '{post_data['name']}'")
                    update_data = {'startupName': post_data["name"], 'updated_at': datetime.utcnow().isoformat()}
                    update_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups/{profile_id}.json"
                    requests.patch(update_path, json=update_data, timeout=10)
            else:
                # ---> THE FIX: If no profile exists, create 'new_profile' here
                print(f"🤷 No profile found for {current_user.email}. Creating a new one.")
                new_profile_id = str(uuid4())
                new_profile = {
                    "id": new_profile_id,
                    "startupName": post_data["name"],
                    "contactEmail": current_user.email,
                    "contactName": getattr(current_user, 'name', current_user.email),
                    "createdAt": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                profile_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups/{new_profile_id}.json"
                profile_response = requests.put(profile_path, json=new_profile, timeout=10)
                
                if profile_response.status_code in (200, 201):
                    print(f"✅ Created startup profile successfully for {current_user.email}")
                else:
                    print(f"⚠️ Failed to create startup profile: {profile_response.status_code} - {profile_response.text}")

        except requests.exceptions.RequestException as e:
            print(f"❌ Firebase profile check error: {str(e)}")
            # Decide if this should be a fatal error or not. Here we let it pass but log it.

        # 5. Create the post object
        post_object = {
            "id": str(uuid4()),
            "startup_name": post_data["name"],
            "tagline": post_data["tagline"],
            "job_title": post_data["title"],
            "skills": post_data["skills"],
            "description": post_data["description"],
            "image_url": image_url,
            "created_at": datetime.utcnow().isoformat(),
            "status": "published",
            "created_by_email": current_user.email,
            "created_by_name": getattr(current_user, 'name', current_user.email),
            "likes_count": 0,
            "shares_count": 0,
            "application_count": 0
        }

        # 6. Store the post in Firebase
        if not POSTS_FIREBASE_URL:
            raise HTTPException(status_code=500, detail="Posts Firebase URL not configured")

        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_object['id']}.json"
        print(f"🔥 Storing post in Firebase: {firebase_path}")

        response = requests.put(firebase_path, json=post_object, timeout=10)
        response.raise_for_status() # Will raise an exception for non-2xx status codes

        print("✅ Post stored successfully in Firebase")

        # Invalidate posts cache (placeholder logic)
        if posts_cache.get('lock'):
            async with posts_cache['lock']:
                posts_cache['data'] = None
                posts_cache['timestamp'] = None
        
        return JSONResponse({
            "success": True,
            "message": "Post published successfully!",
            "post_id": post_object["id"],
            "redirect_url": "/startups/home"
        })

    except HTTPException:
        raise  # Re-raise FastAPI's HTTPExceptions
    except requests.exceptions.RequestException as e:
        print(f"❌ Firebase request error: {str(e)}")
        raise HTTPException(status_code=503, detail="Database connection error.")
    except Exception as e:
        print(f"💥 Unexpected error in create_post: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected internal error occurred.")



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
                # Clean the post data
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
                
                return JSONResponse({
                    "success": True,
                    "post": clean_post
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
    limit: int = Query(5, ge=1, le=20, description="Number of posts per page"),
    start_after: Optional[str] = Query(None, description="Cursor for pagination")
):
    """
    Get posts with 10 MINUTE SMART CACHING - Perfect balance!
    """
    try:
        # Check authentication
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if not POSTS_FIREBASE_URL:
            raise HTTPException(status_code=500, detail="Posts Firebase URL not configured")
        
        # 🎯 SMART CACHE CHECK (10 MINUTES)
        async with posts_cache['lock']:
            cache_valid = (
                posts_cache['data'] is not None and 
                posts_cache['timestamp'] is not None and
                datetime.utcnow() - posts_cache['timestamp'] < CACHE_DURATION
            )
            
            if cache_valid:
                # ⚡ CACHE HIT - Instant response!
                posts_data = posts_cache['data']
                cache_status = "hit"
                print("✨ Posts Cache HIT - Serving from memory (10 min cache)")
            else:
                # 🔥 CACHE MISS - Fetch from Firebase
                print("🔥 Posts Cache MISS - Fetching from Firebase")
                cache_status = "miss"
                
                firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts.json"
                
                try:
                    response = requests.get(firebase_path, timeout=10)
                    
                    if response.status_code == 200:
                        posts_data = response.json()
                        # ✅ Update cache with fresh data
                        posts_cache['data'] = posts_data
                        posts_cache['timestamp'] = datetime.utcnow()
                        print(f"✅ Posts cache updated (valid for 10 minutes) with {len(posts_data) if posts_data else 0} items")
                    else:
                        # Use stale cache if available
                        if posts_cache['data'] is not None:
                            posts_data = posts_cache['data']
                            cache_status = "stale"
                            print("⚠️ Using stale posts cache due to Firebase error")
                        else:
                            raise HTTPException(status_code=500, detail="Firebase error")
                            
                except requests.exceptions.RequestException as e:
                    # Network error - use stale cache if available
                    if posts_cache['data'] is not None:
                        posts_data = posts_cache['data']
                        cache_status = "stale"
                        print(f"⚠️ Using stale posts cache due to network error: {str(e)}")
                    else:
                        raise HTTPException(status_code=503, detail="Service unavailable")
        
        # Handle empty data
        if not posts_data:
            return {
                "success": True,
                "posts": [],
                "returned_count": 0,
                "next_cursor": None,
                "has_more": False,
                "cache_status": cache_status
            }
        
        # Process posts
        posts_list = []
        for post_id, post_data in posts_data.items():
            if post_data and isinstance(post_data, dict) and post_data.get('status') == 'published':
                posts_list.append({
                    'id': post_data.get('id', post_id),
                    'startup_name': post_data.get('startup_name', 'Unknown Startup'),
                    'tagline': post_data.get('tagline', ''),
                    'job_title': post_data.get('job_title', 'Position Available'),
                    'skills': post_data.get('skills', ''),
                    'description': post_data.get('description', ''),
                    'image_url': post_data.get('image_url', ''),
                    'created_at': post_data.get('created_at', ''),
                    'status': post_data.get('status', 'published'),
                    'location': post_data.get('location', ''),
                    'duration': post_data.get('duration', ''),
                    'stipend': post_data.get('stipend', ''),
                    'application_count': post_data.get('application_count', 0),
                    'likes_count': post_data.get('likes_count', 0),
                    'created_by_email': post_data.get('created_by_email')
                })
        
        # Sort by creation date (newest first)
        posts_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Pagination logic
        start_index = 0
        if start_after:
            for i, post in enumerate(posts_list):
                if post['id'] == start_after:
                    start_index = i + 1
                    break
        
        end_index = start_index + limit
        paginated_posts = posts_list[start_index:end_index]
        has_more = end_index < len(posts_list)
        next_cursor = paginated_posts[-1]['id'] if has_more and paginated_posts else None
        
        return {
            "success": True,
            "posts": paginated_posts,
            "returned_count": len(paginated_posts),
            "total_count": len(posts_list),
            "next_cursor": next_cursor,
            "has_more": has_more,
            "cache_status": cache_status,
            "cache_age_seconds": int((datetime.utcnow() - posts_cache['timestamp']).total_seconds()) if posts_cache['timestamp'] else None,
            "cache_duration_minutes": 10
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Error in get_all_posts: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/invalidate_posts_cache")
async def invalidate_posts_cache(current_user: User = Depends(get_current_user)):
    """Manually clear posts cache"""
    async with posts_cache['lock']:
        posts_cache['data'] = None
        posts_cache['timestamp'] = None
    
    return {"success": True, "message": "Posts cache cleared"}

@app.post("/api/invalidate_profiles_cache")
async def invalidate_profiles_cache(current_user: User = Depends(get_current_user)):
    """Manually clear profiles cache"""
    async with profiles_cache['lock']:
        profiles_cache['data'] = None
        profiles_cache['timestamp'] = None
    
    return {"success": True, "message": "Profiles cache cleared"}

@app.get("/get_startup_profiles/")
@app.get("/get_startup_profiles")
async def get_startup_profiles(
    current_user: User = Depends(get_current_user),
    startup_name: Optional[str] = Query(None, description="Specific startup name to fetch"),
    email: Optional[str] = Query(None, description="Startup email to fetch")
):
    """
    Get a specific startup profile with fallback lookup methods
    """
    # Authorization check first
    if current_user.role != "intern":
        raise HTTPException(status_code=403, detail="Access denied.")

    # Check if a specific profile is requested
    if not startup_name and not email:
        raise HTTPException(status_code=400, detail="A startup_name or email is required.")

    startup_profile_data = None

    try:
        firebase_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups.json"
        
        # Try primary lookup method
        if startup_name:
            print(f"🔍 Querying Firebase for startup with name: '{startup_name}'")
            query_params = {'orderBy': '"startupName"', 'equalTo': f'"{startup_name}"'}
        else:
            print(f"🔍 Querying Firebase for startup with email: '{email}'")
            query_params = {'orderBy': '"contactEmail"', 'equalTo': f'"{email}"'}
        
        response = requests.get(firebase_path, params=query_params, timeout=10)
        response.raise_for_status()
        found_profiles = response.json()

        # If no profile found by contactEmail, try alternative lookup by key
        if not found_profiles and email:
            print(f"🔄 No profile found by contactEmail, trying key-based lookup...")
            
            # Convert email to Firebase key format (replace @ and . with _)
            email_key = email.replace('@', '_').replace('.', '_')
            direct_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups/{email_key}.json"
            
            direct_response = requests.get(direct_path, timeout=10)
            if direct_response.status_code == 200 and direct_response.json():
                print(f"✅ Found profile by key: {email_key}")
                found_profiles = {email_key: direct_response.json()}
            else:
                # Try fetching all profiles and search manually
                print(f"🔍 Fetching all profiles to search for posts created by: {email}")
                all_response = requests.get(firebase_path, timeout=10)
                if all_response.status_code == 200:
                    all_profiles = all_response.json() or {}
                    
                    # Look for profiles where the key matches the email pattern
                    for profile_id, profile_data in all_profiles.items():
                        if profile_id == email_key or (
                            isinstance(profile_data, dict) and 
                            profile_data.get('created_by_email') == email
                        ):
                            found_profiles = {profile_id: profile_data}
                            print(f"✅ Found profile by alternate search: {profile_id}")
                            break

        if found_profiles:
            profile_id = next(iter(found_profiles))
            profile_data = found_profiles[profile_id]
            
            print(f"✅ Found profile with ID: {profile_id}")

            startup_profile_data = {
                'id': profile_id,
                'startupName': profile_data.get('startupName', '') or profile_data.get('startup_name', ''),
                'logo': profile_data.get('logo', ''),
                'foundingYear': profile_data.get('foundingYear', ''),
                'locationType': profile_data.get('locationType', ''),
                'physicalLocation': profile_data.get('physicalLocation', ''),
                'founders': profile_data.get('founders', []),
                'contactEmail': profile_data.get('contactEmail', ''),
                'website': profile_data.get('website', ''),
                'description': profile_data.get('description', ''),
                'contactPhone': profile_data.get('contactPhone', ''),
                'createdAt': profile_data.get('createdAt', ''),
                'updated_at': profile_data.get('updated_at', '')
            }
        else:
            print(f"❌ No profile found for the given criteria.")

    except requests.exceptions.RequestException as e:
        print(f"💥 Firebase request error in get_startup_profiles: {str(e)}")
        raise HTTPException(status_code=503, detail="Database connection error.")
    except Exception as e:
        print(f"💥 Unexpected error in get_startup_profiles: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")

    # Final Response
    if startup_profile_data:
        return {
            "success": True,
            "startup": startup_profile_data
        }
    else:
        return {
            "success": False,
            "startup": None,
            "message": "Startup profile not found."
        }



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

@app.get("/startup/profile/view")
async def view_startup_profile_page(request: Request, current_user: User = Depends(get_current_user)):
    """
    View individual startup profile page - accessible only to authenticated interns
    """
    try:
        # Check if user is authenticated intern
        if current_user.role != "intern":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only interns can view startup profiles."
            )
        
        return templates.TemplateResponse("interns/view_startup_profile.html", {"request": request})
    
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e


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


chat_messages = {}  # {conversation_id: [messages]}
message_timestamps = {}  # {message_id: timestamp}
connected_users = {}  # {socket_id: user_email}
user_sockets = defaultdict(list)  # {user_email: [socket_ids]}
cleanup_lock = threading.Lock()

# Socket.IO setup (replace your existing setup)
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=[
        "https://myeduconnect.onrender.com", 
        "http://localhost:8000", 
        "http://127.0.0.1:8000"
    ],
    logger=True,
    engineio_logger=False  # Set to True for debugging
)

# Create Socket.IO app AFTER FastAPI app is created
# (move this line after app = FastAPI())
socket_app = socketio.ASGIApp(sio, app)

# Clean up function for 24-hour message deletion
def cleanup_old_messages():
    """Remove messages older than 24 hours"""
    with cleanup_lock:
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(hours=24)
        
        messages_to_remove = []
        for message_id, timestamp in list(message_timestamps.items()):
            if timestamp < cutoff_time:
                messages_to_remove.append(message_id)
        
        # Remove old messages
        for message_id in messages_to_remove:
            del message_timestamps[message_id]
            
            # Remove from chat_messages
            for conv_id in list(chat_messages.keys()):
                chat_messages[conv_id] = [
                    msg for msg in chat_messages[conv_id] 
                    if msg.get('id') != message_id
                ]
                if not chat_messages[conv_id]:  # Remove empty conversations
                    del chat_messages[conv_id]
        
        print(f"Cleaned up {len(messages_to_remove)} old messages")
    
    # Schedule next cleanup in 1 hour
    Timer(3600, cleanup_old_messages).start()

# Start the cleanup timer
Timer(10, cleanup_old_messages).start()  # Start after 10 seconds

# Socket.IO Events
@sio.event
async def connect(sid, environ):
    """Handle new socket connections"""
    print(f"Client {sid} attempting to connect")
    
    try:
        # Get authorization from multiple sources
        auth_header = environ.get('HTTP_AUTHORIZATION', '')
        cookie_header = environ.get('HTTP_COOKIE', '')
        
        token = None
        
        # Try to get token from Authorization header first
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            print(f"Token found in Authorization header for {sid}")
        
        # If not in header, try cookies
        if not token and cookie_header:
            cookies = {}
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
            token = cookies.get('access_token')
            if token:
                print(f"Token found in cookies for {sid}")
        
        if not token:
            print(f"No token found for {sid}, rejecting connection")
            return False  # Reject connection
        
        # Verify JWT token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            
            if not email:
                print(f"Invalid token payload for {sid}")
                return False
            
            # Verify user exists
            user = get_user(email)
            if not user:
                print(f"User {email} not found for {sid}")
                return False
            
            # Store user connection
            connected_users[sid] = email
            user_sockets[email].append(sid)
            
            # Store user info in session
            await sio.save_session(sid, {'user_email': email, 'user_role': user.role})
            
            print(f"✅ User {email} connected with socket {sid}")
            
            # Send confirmation
            await sio.emit('connected', {
                'message': 'Successfully connected',
                'user_email': email,
                'socket_id': sid
            }, to=sid)
            
            return True  # Accept connection
            
        except JWTError as e:
            print(f"JWT decode error for {sid}: {str(e)}")
            return False
            
    except Exception as e:
        print(f"Connection error for {sid}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
@sio.event
async def disconnect(sid):
    """Handle socket disconnections"""
    print(f"Client {sid} disconnecting")
    
    if sid in connected_users:
        user_email = connected_users[sid]
        del connected_users[sid]
        
        if user_email in user_sockets:
            user_sockets[user_email].remove(sid)
            if not user_sockets[user_email]:
                del user_sockets[user_email]
        
        print(f"✅ User {user_email} disconnected (socket {sid})")

@sio.event
async def send_message(sid, data):
    """Handle sending messages between users"""
    try:
        # Verify authentication
        if sid not in connected_users:
            await sio.emit('error', {'message': 'Not authenticated'}, room=sid)
            return
        
        sender_email = connected_users[sid]
        recipient_email = data.get('to')
        message_text = data.get('message')
        
        # Validate input
        if not recipient_email or not message_text:
            await sio.emit('error', {'message': 'Missing recipient or message'}, room=sid)
            return
        
        # Create message
        message_id = str(uuid4())
        timestamp = datetime.utcnow()
        
        message_obj = {
            'id': message_id,
            'from': sender_email,
            'to': recipient_email,
            'message': message_text,
            'timestamp': timestamp.isoformat(),
            'read': False
        }
        
        # Store message in memory
        with cleanup_lock:
            # Create conversation ID (sorted emails for consistency)
            conversation_id = '_'.join(sorted([sender_email, recipient_email]))
            
            if conversation_id not in chat_messages:
                chat_messages[conversation_id] = []
            
            chat_messages[conversation_id].append(message_obj)
            message_timestamps[message_id] = timestamp
        
        # Send to recipient if online
        if recipient_email in user_sockets:
            for recipient_sid in user_sockets[recipient_email]:
                await sio.emit('receive_message', {
                    'from': sender_email,
                    'message': message_text,
                    'timestamp': message_obj['timestamp'],
                    'id': message_id
                }, room=recipient_sid)
        
        # Confirm to sender
        await sio.emit('message_sent', {
            'to': recipient_email,
            'message': message_text,
            'timestamp': message_obj['timestamp'],
            'id': message_id
        }, room=sid)
        
        print(f"📨 Message sent: {sender_email} → {recipient_email}")
        
    except Exception as e:
        print(f"Error in send_message: {str(e)}")
        await sio.emit('error', {'message': 'Failed to send message'}, room=sid)

@sio.event
async def get_chat_history(sid, data):
    """Get chat history with a specific user"""
    try:
        if sid not in connected_users:
            await sio.emit('error', {'message': 'Not authenticated'}, room=sid)
            return
        
        current_user = connected_users[sid]
        other_user = data.get('with')
        
        if not other_user:
            await sio.emit('error', {'message': 'Missing user parameter'}, room=sid)
            return
        
        # Get conversation
        with cleanup_lock:
            conversation_id = '_'.join(sorted([current_user, other_user]))
            messages = chat_messages.get(conversation_id, [])
            
            # Sort by timestamp
            sorted_messages = sorted(messages, key=lambda x: x['timestamp'])
        
        await sio.emit('chat_history', {
            'with': other_user,
            'messages': sorted_messages
        }, room=sid)
        
    except Exception as e:
        print(f"Error in get_chat_history: {str(e)}")
        await sio.emit('error', {'message': 'Failed to get chat history'}, room=sid)

@sio.event
async def typing(sid, data):
    """Handle typing indicators"""
    try:
        if sid not in connected_users:
            return
        
        sender = connected_users[sid]
        recipient = data.get('to')
        is_typing = data.get('typing', False)
        
        if recipient and recipient in user_sockets:
            for recipient_sid in user_sockets[recipient]:
                await sio.emit('user_typing', {
                    'from': sender,
                    'typing': is_typing
                }, room=recipient_sid)
                
    except Exception as e:
        print(f"Error in typing event: {str(e)}")

# Add the chat page route
@app.get("/chat")
async def chat_page(request: Request, current_user: User = Depends(get_current_user)):
    """Serve the chat page"""
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": current_user
    })

# API endpoint to get active users (optional)
@app.get("/api/chat/users")
async def get_chat_users(current_user: User = Depends(get_current_user)):
    """Get list of users to chat with"""
    try:
        # Get all users from MongoDB except current user
        users = []
        cursor = users_collection.find(
            {"email": {"$ne": current_user.email}},
            {"email": 1, "name": 1, "role": 1, "_id": 0}
        ).limit(50)  # Limit to 50 users for performance
        
        async for user in cursor:
            users.append({
                "email": user["email"],
                "name": user.get("name", user["email"]),
                "role": user.get("role", "unknown"),
                "online": user["email"] in user_sockets
            })
        
        return {"success": True, "users": users}
        
    except Exception as e:
        print(f"Error getting chat users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get users")

# Update the main execution block
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        socket_app,  # Use socket_app instead of app
        host="0.0.0.0",
        port=8000,
        reload=True,  # Set to False in production
        proxy_headers=True,
        forwarded_allow_ips="*"
    )