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
# In-memory chat storage with automatic cleanup
chat_messages = []  # List of all messages with timestamps
user_connections = {}  # {user_email: [socket_ids]}
socket_users = {}  # {socket_id: user_email}
message_lock = threading.Lock()



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
    """Serve the getstarted page for non-authenticated users"""
    try:
        # Try to get current user
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                email = payload.get("sub")
                if email:
                    # User is authenticated, redirect to appropriate home
                    user = users_collection.find_one(
                        {"email": email},
                        {"role": 1, "_id": 0}
                    )
                    if user:
                        if user.get("role") == "startup":
                            return RedirectResponse(url="/startups/home", status_code=302)
                        elif user.get("role") == "intern":
                            return RedirectResponse(url="/interns/home", status_code=302)
            except (jwt.PyJWTError, Exception):
                # Invalid token, serve getstarted page
                pass
        
        # No valid auth, serve getstarted page
        return templates.TemplateResponse("getstarted.html", {
            "request": request
        })
        
    except Exception:
        # Any error, serve getstarted page
        return templates.TemplateResponse("getstarted.html", {
            "request": request
        })

@app.get("/login", include_in_schema=True)
@app.head("/login", include_in_schema=True)
async def login_page(request: Request, logout: Optional[str] = None):
    """Serve the login page"""
    # If logout parameter exists, don't check for existing auth
    if logout:
        response = templates.TemplateResponse("index.html", {
            "request": request
        })
        response.delete_cookie("access_token")
        return response
    
    # Check for existing valid token only if not logging out
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

@app.get("/api/my-profile")
async def get_my_profile(current_user: User = Depends(get_current_user)):
    """
    Get current user's profile data
    """
    try:
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        
        if current_user.role == "intern":
            firebase_path = f"{FIREBASE_URL.rstrip('/')}/interns/{safe_email}.json"
        elif current_user.role == "startup":
            firebase_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups/{safe_email}.json"
        else:
            raise HTTPException(status_code=400, detail="Invalid user role")
        
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code == 200:
            profile_data = response.json()
            if profile_data:
                return JSONResponse({
                    "success": True,
                    "profile": profile_data
                })
            else:
                return JSONResponse({
                    "success": False,
                    "message": "Profile not found",
                    "profile": None
                })
        else:
            return JSONResponse({
                "success": False,
                "message": "Failed to fetch profile",
                "profile": None
            })
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")



@app.get("/api/search_posts_by_startup")
async def search_posts_by_startup(
    startup_name: str = Query(..., description="Startup name to search for"),
    current_user: User = Depends(get_current_user)
):
    """
    Search posts by startup name
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if not POSTS_FIREBASE_URL:
            raise HTTPException(status_code=500, detail="Posts Firebase URL not configured")
        
        # Get all posts from Firebase
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch posts")
        
        posts_data = response.json() or {}
        
        # Filter posts by startup name
        matching_posts = []
        search_name = startup_name.lower().strip()
        
        for post_id, post_data in posts_data.items():
            if (post_data and isinstance(post_data, dict) and 
                post_data.get('status') == 'published' and
                search_name in post_data.get('startup_name', '').lower()):
                
                matching_posts.append({
                    'id': post_data.get('id', post_id),
                    'startup_name': post_data.get('startup_name', 'Unknown Startup'),
                    'tagline': post_data.get('tagline', ''),
                    'job_title': post_data.get('job_title', 'Position Available'),
                    'skills': post_data.get('skills', ''),
                    'description': post_data.get('description', ''),
                    'image_url': post_data.get('image_url', ''),
                    'created_at': post_data.get('created_at', ''),
                    'likes_count': post_data.get('likes_count', 0),
                    'shares_count': post_data.get('shares_count', 0),
                    'is_liked': False,
                    'is_saved': False,
                    'created_by_email': post_data.get('created_by_email')
                })
        
        # Batch check like/save status
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        
        if matching_posts:
            try:
                # Batch check likes
                likes_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/likes.json"
                likes_response = requests.get(likes_path, timeout=3)
                user_likes = {}
                if likes_response.status_code == 200 and likes_response.json():
                    all_likes = likes_response.json()
                    for post_id, likes_data in all_likes.items():
                        if likes_data and safe_email in likes_data:
                            user_likes[post_id] = True
                
                # Batch check saves
                saves_path = f"{SAVED_POSTS_FIREBASE_URL.rstrip('/')}/saved_posts/{safe_email}.json"
                saves_response = requests.get(saves_path, timeout=3)
                user_saves = set()
                if saves_response.status_code == 200 and saves_response.json():
                    user_saves = set(saves_response.json().keys())
                
                # Apply to posts
                for post in matching_posts:
                    post['is_liked'] = user_likes.get(post['id'], False)
                    post['is_saved'] = post['id'] in user_saves
            except:
                for post in matching_posts:
                    post['is_liked'] = False
                    post['is_saved'] = False
        
        # Sort by creation date (newest first)
        matching_posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return {
            "success": True,
            "posts": matching_posts,
            "count": len(matching_posts),
            "search_query": startup_name
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in search_posts_by_startup: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/get_all_posts")
async def get_all_posts(
    current_user: User = Depends(get_current_user),
    limit: int = Query(5, ge=1, le=20, description="Number of posts per page"),
    start_after: Optional[str] = Query(None, description="Cursor for pagination")
):
    """
    Get posts with ULTRA-FAST OPTIMIZED CACHING - Sub-second response!
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if not POSTS_FIREBASE_URL:
            raise HTTPException(status_code=500, detail="Posts Firebase URL not configured")
        
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        
        # 🎯 SMART CACHE CHECK (10 MINUTES)
        async with posts_cache['lock']:
            cache_valid = (
                posts_cache['data'] is not None and 
                posts_cache['timestamp'] is not None and
                datetime.utcnow() - posts_cache['timestamp'] < CACHE_DURATION
            )
            
            if cache_valid:
                posts_data = posts_cache['data']
                cache_status = "hit"
            else:
                cache_status = "miss"
                firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts.json"
                
                try:
                    response = requests.get(firebase_path, timeout=8)
                    if response.status_code == 200:
                        posts_data = response.json()
                        posts_cache['data'] = posts_data
                        posts_cache['timestamp'] = datetime.utcnow()
                    else:
                        if posts_cache['data'] is not None:
                            posts_data = posts_cache['data']
                            cache_status = "stale"
                        else:
                            raise HTTPException(status_code=500, detail="Firebase error")
                except requests.exceptions.RequestException:
                    if posts_cache['data'] is not None:
                        posts_data = posts_cache['data']
                        cache_status = "stale"
                    else:
                        raise HTTPException(status_code=503, detail="Service unavailable")
        
        if not posts_data:
            return {
                "success": True,
                "posts": [],
                "returned_count": 0,
                "next_cursor": None,
                "has_more": False,
                "cache_status": cache_status
            }
        
        # Process posts efficiently
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
                    'likes_count': post_data.get('likes_count', 0),
                    'shares_count': post_data.get('shares_count', 0),
                    'is_liked': False,
                    'is_saved': False,
                    'created_by_email': post_data.get('created_by_email')
                })
        
        posts_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Pagination first, then batch check status
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
        
        # ⚡ BATCH CHECK LIKES/SAVES - Only for paginated posts
        if paginated_posts:
            try:
                # Batch check likes
                likes_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/likes.json"
                likes_response = requests.get(likes_path, timeout=3)
                user_likes = {}
                if likes_response.status_code == 200 and likes_response.json():
                    all_likes = likes_response.json()
                    for post_id, likes_data in all_likes.items():
                        if likes_data and safe_email in likes_data:
                            user_likes[post_id] = True
                
                # Batch check saves
                saves_path = f"{SAVED_POSTS_FIREBASE_URL.rstrip('/')}/saved_posts/{safe_email}.json"
                saves_response = requests.get(saves_path, timeout=3)
                user_saves = set()
                if saves_response.status_code == 200 and saves_response.json():
                    user_saves = set(saves_response.json().keys())
                
                # Apply status to posts
                for post in paginated_posts:
                    post['is_liked'] = user_likes.get(post['id'], False)
                    post['is_saved'] = post['id'] in user_saves
                    
            except:
                pass  # Fail silently, defaults to False
        
        return {
            "success": True,
            "posts": paginated_posts,
            "returned_count": len(paginated_posts),
            "total_count": len(posts_list),
            "next_cursor": next_cursor,
            "has_more": has_more,
            "cache_status": cache_status
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
    Like/Unlike a post with proper user tracking
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
        
        # Check if user has already liked this post
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        likes_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/likes/{post_id}/{safe_email}.json"
        
        # Check if like exists
        like_check = requests.get(likes_path, timeout=10)
        already_liked = like_check.status_code == 200 and like_check.json() is not None
        
        if already_liked:
            # Unlike the post
            delete_response = requests.delete(likes_path, timeout=10)
            if delete_response.status_code not in [200, 204]:
                raise HTTPException(status_code=500, detail="Failed to unlike post")
            
            # Decrement likes count
            current_likes = post_data.get('likes_count', 1)
            updated_likes = max(0, current_likes - 1)
            action = "unliked"
        else:
            # Like the post
            like_data = {
                "user_email": current_user.email,
                "liked_at": datetime.utcnow().isoformat()
            }
            put_response = requests.put(likes_path, json=like_data, timeout=10)
            if put_response.status_code not in [200, 201]:
                raise HTTPException(status_code=500, detail="Failed to like post")
            
            # Increment likes count
            current_likes = post_data.get('likes_count', 0)
            updated_likes = current_likes + 1
            action = "liked"
        
        # Update Firebase with new likes count
        update_data = {'likes_count': updated_likes}
        update_response = requests.patch(firebase_path, json=update_data, timeout=10)
        
        if update_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to update likes count")
        
        # Invalidate posts cache
        async with posts_cache['lock']:
            posts_cache['data'] = None
            posts_cache['timestamp'] = None
        
        return {
            "success": True,
            "action": action,
            "message": f"Post {action} successfully",
            "likes_count": updated_likes,
            "is_liked": not already_liked
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error liking post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/share_post/{post_id}")
async def share_post(post_id: str, request: Request, current_user: User = Depends(get_current_user)):
    """
    Share a post (increment share count and generate unique link)
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
        
        # Generate the unique shareable URL
        base_url = str(request.base_url).rstrip('/')
        share_url = f"{base_url}/post/{post_id}"
        
        # Invalidate posts cache
        async with posts_cache['lock']:
            posts_cache['data'] = None
            posts_cache['timestamp'] = None
        
        return {
            "success": True,
            "message": "Post shared successfully",
            "shares_count": updated_shares,
            "share_url": share_url
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sharing post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/save_post/{post_id}")
async def save_post(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Save a post for the current user
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get the post data first to validate it exists
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail="Post not found")
        
        post_data = response.json()
        if not post_data:
            raise HTTPException(status_code=404, detail="Post not found")
        
        # Create saved post entry
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        saved_post_data = {
            "post_id": post_id,
            "user_email": current_user.email,
            "saved_at": datetime.utcnow().isoformat(),
            "post_data": post_data  # Store the post data for quick access
        }
        
        # Save to Firebase
        saved_posts_path = f"{SAVED_POSTS_FIREBASE_URL.rstrip('/')}/saved_posts/{safe_email}/{post_id}.json"
        save_response = requests.put(saved_posts_path, json=saved_post_data, timeout=10)
        
        if save_response.status_code not in [200, 201]:
            raise HTTPException(status_code=500, detail="Failed to save post")
        
        return {
            "success": True,
            "message": "Post saved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error saving post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/unsave_post/{post_id}")
async def unsave_post(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Remove a saved post for the current user
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Remove from Firebase
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        saved_posts_path = f"{SAVED_POSTS_FIREBASE_URL.rstrip('/')}/saved_posts/{safe_email}/{post_id}.json"
        
        delete_response = requests.delete(saved_posts_path, timeout=10)
        
        # Firebase returns 200 even if the item doesn't exist, so we don't need to check
        return {
            "success": True,
            "message": "Post removed from saved posts"
        }
        
    except Exception as e:
        print(f"Error unsaving post: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/saved_posts")
async def get_saved_posts(current_user: User = Depends(get_current_user)):
    """
    Get all saved posts for the current user
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get saved posts from Firebase
        safe_email = re.sub(r"[^A-Za-z0-9]", "_", current_user.email)
        saved_posts_path = f"{SAVED_POSTS_FIREBASE_URL.rstrip('/')}/saved_posts/{safe_email}.json"
        
        response = requests.get(saved_posts_path, timeout=10)
        
        if response.status_code != 200:
            return {
                "success": True,
                "saved_posts": []
            }
        
        saved_posts_data = response.json() or {}
        
        # Convert to list and sort by saved_at (newest first)
        saved_posts = []
        for post_id, saved_data in saved_posts_data.items():
            if saved_data and isinstance(saved_data, dict):
                saved_posts.append({
                    "post_id": post_id,
                    "saved_at": saved_data.get("saved_at"),
                    "post_data": saved_data.get("post_data", {})
                })
        
        # Sort by saved_at (newest first)
        saved_posts.sort(key=lambda x: x.get("saved_at", ""), reverse=True)
        
        return {
            "success": True,
            "saved_posts": saved_posts
        }
        
    except Exception as e:
        print(f"Error getting saved posts: {str(e)}")
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

@app.get("/saved-posts")
async def saved_posts_page(request: Request, current_user: User = Depends(get_current_user)):
    """
    Display saved posts page - accessible only to authenticated interns
    """
    try:
        # Check if user is authenticated intern
        if current_user.role != "intern":
            raise HTTPException(
                status_code=403, 
                detail="Access denied. Only interns can view saved posts."
            )
        
        return templates.TemplateResponse("saved_posts.html", {"request": request})
    
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e


@app.get("/post/{post_id}")
async def public_post_view(post_id: str, request: Request):
    """
    Public post view - accessible without authentication for sharing
    """
    try:
        if not POSTS_FIREBASE_URL:
            raise HTTPException(status_code=500, detail="Posts Firebase URL not configured")
        
        # Get post data
        firebase_path = f"{POSTS_FIREBASE_URL.rstrip('/')}/posts/{post_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code != 200 or not response.json():
            # Post not found - redirect to login
            return RedirectResponse(url="/login", status_code=303)
        
        post_data = response.json()
        
        # Get startup profile if available
        startup_profile = None
        if post_data.get('created_by_email'):
            try:
                profile_query_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups.json"
                query_params = {'orderBy': '"contactEmail"', 'equalTo': f'"{post_data["created_by_email"]}"'}
                profile_response = requests.get(profile_query_path, params=query_params, timeout=10)
                
                if profile_response.status_code == 200:
                    profiles = profile_response.json()
                    if profiles:
                        startup_profile = next(iter(profiles.values()))
            except:
                pass  # Fail silently for profile fetch
        
        # Check if user is authenticated
        user_authenticated = False
        user_role = None
        try:
            token = request.cookies.get("access_token")
            if token:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                email = payload.get("sub")
                if email:
                    user = get_user(email)
                    if user:
                        user_authenticated = True
                        user_role = user.role
        except:
            pass  # User not authenticated
        
        # Prepare post data for template
        post_display = {
            'id': post_data.get('id', post_id),
            'startup_name': post_data.get('startup_name', 'Unknown Startup'),
            'tagline': post_data.get('tagline', ''),
            'job_title': post_data.get('job_title', 'Position Available'),
            'skills': post_data.get('skills', ''),
            'description': post_data.get('description', ''),
            'image_url': post_data.get('image_url', ''),
            'created_at': post_data.get('created_at', ''),
            'likes_count': post_data.get('likes_count', 0),
            'shares_count': post_data.get('shares_count', 0),
            'startup_profile': startup_profile
        }
        
        # Render the public post view template
        return templates.TemplateResponse("public_post.html", {
            "request": request,
            "post": post_display,
            "authenticated": user_authenticated,
            "user_role": user_role
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error viewing public post: {str(e)}")
        return RedirectResponse(url="/", status_code=303)


# Add this at the top with other Firebase URLs
CHATS_FIREBASE_URL = os.getenv("FIREBASE_CHATS_DATABASE")
SAVED_POSTS_FIREBASE_URL = os.getenv("FIREBASE_SAVED_POSTS_DATABASE", FIREBASE_URL)  # Use same as intern DB if not specified

# Chat cache for ultra bandwidth saving
chat_cache = {
    'conversations': {'data': None, 'timestamp': None},
    'messages': {},  # {conversation_id: {'data': [], 'timestamp': datetime}}
    'lock': asyncio.Lock()
}
CHAT_CACHE_DURATION = timedelta(minutes=5)  # 5 minute cache

# Debug: Print Firebase URLs at startup
print(f"🔥 Firebase URLs configured:")
print(f"   FIREBASE_URL: {FIREBASE_URL}")
print(f"   STARTUP_FIREBASE_URL: {STARTUP_FIREBASE_URL}")
print(f"   POSTS_FIREBASE_URL: {POSTS_FIREBASE_URL}")
print(f"   CHATS_FIREBASE_URL: {CHATS_FIREBASE_URL}")
print(f"   SAVED_POSTS_FIREBASE_URL: {SAVED_POSTS_FIREBASE_URL}")

if not CHATS_FIREBASE_URL:
    print("⚠️ WARNING: CHATS_FIREBASE_URL not configured - chat functionality will not work!")

# Remove these in-memory storage variables (DELETE THESE LINES):
# chat_messages = {}
# message_timestamps = {}
# cleanup_lock = threading.Lock()

# Keep these for socket management only:
connected_users = {}  # {socket_id: user_email}
user_sockets = defaultdict(list)  # {user_email: [socket_ids]}

# Remove the cleanup function and timer (DELETE THESE):
# def cleanup_old_messages(): ...
# Timer(10, cleanup_old_messages).start()

@app.post("/api/message_startup")
async def message_startup(
    startup_name: str = Form(...),
    message: str = Form(...),
    current_user: User = Depends(get_current_user)
):
    """
    Send message to startup - now integrated with chat system
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Find startup email by name
        firebase_path = f"{STARTUP_FIREBASE_URL.rstrip('/')}/startups.json"
        query_params = {'orderBy': '"startupName"', 'equalTo': f'"{startup_name}"'}
        response = requests.get(firebase_path, params=query_params, timeout=10)
        
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail="Startup not found")
        
        startup_data = response.json()
        if not startup_data:
            raise HTTPException(status_code=404, detail="Startup not found")
        
        # Get startup email
        startup_info = next(iter(startup_data.values()))
        startup_email = startup_info.get('contactEmail', '')
        
        if not startup_email:
            raise HTTPException(status_code=404, detail="Startup email not found")
        
        # Create message using chat system
        message_id = str(uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        # Sanitize emails for Firebase path
        safe_current = re.sub(r'[^A-Za-z0-9]', '_', current_user.email)
        safe_startup = re.sub(r'[^A-Za-z0-9]', '_', startup_email)
        conversation_id = '_'.join(sorted([safe_current, safe_startup]))
        
        message_obj = {
            'id': message_id,
            'from': current_user.email,
            'to': startup_email,
            'message': message,
            'timestamp': timestamp,
            'read': False,
            'delivered': False,
            'startup_name': startup_name  # Additional context
        }
        
        # Use dedicated chat Firebase URL
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            raise HTTPException(status_code=500, detail="Chat service not configured")
        
        # Save to Firebase chat database
        chat_path = f"{chat_firebase_url.rstrip('/')}/conversations/{conversation_id}/messages/{message_id}.json"
        response = requests.put(chat_path, json=message_obj, timeout=10)
        
        if response.status_code not in [200, 201]:
            raise HTTPException(status_code=500, detail="Failed to send message")
        
        # Update conversation metadata
        conv_meta = {
            'last_message': message,
            'last_message_time': timestamp,
            'participants': [current_user.email, startup_email]
        }
        meta_path = f"{chat_firebase_url.rstrip('/')}/conversations/{conversation_id}/metadata.json"
        requests.put(meta_path, json=conv_meta, timeout=10)
        
        # Send real-time notification if startup is online
        if startup_email in user_sockets:
            for sid in user_sockets[startup_email]:
                await sio.emit('receive_message', {
                    'from': current_user.email,
                    'message': message,
                    'timestamp': timestamp,
                    'id': message_id,
                    'startup_name': startup_name
                }, room=sid)
        
        return {
            "success": True,
            "message": f"Message sent to {startup_name} successfully",
            "message_id": message_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Socket.IO setup remains the same
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

# Create Socket.IO app
socket_app = socketio.ASGIApp(sio, app)

# Socket.IO Events
@sio.event
async def join_conversation(sid, data):
    """Join a conversation room for real-time updates"""
    try:
        if sid not in connected_users:
            return
        
        current_user = connected_users[sid]
        other_user = data.get('with')
        
        if not other_user:
            return
        
        # Create room name
        safe_current = re.sub(r'[^A-Za-z0-9]', '_', current_user)
        safe_other = re.sub(r'[^A-Za-z0-9]', '_', other_user)
        room_name = '_'.join(sorted([safe_current, safe_other]))
        
        # Join the room
        await sio.enter_room(sid, room_name)
        print(f"💬 User {current_user} joined conversation room {room_name}")
        
    except Exception as e:
        print(f"❌ Error joining conversation: {str(e)}")

@sio.event
async def leave_conversation(sid, data):
    """Leave a conversation room"""
    try:
        if sid not in connected_users:
            return
        
        current_user = connected_users[sid]
        other_user = data.get('with')
        
        if not other_user:
            return
        
        # Create room name
        safe_current = re.sub(r'[^A-Za-z0-9]', '_', current_user)
        safe_other = re.sub(r'[^A-Za-z0-9]', '_', other_user)
        room_name = '_'.join(sorted([safe_current, safe_other]))
        
        # Leave the room
        await sio.leave_room(sid, room_name)
        print(f"🚪 User {current_user} left conversation room {room_name}")
        
    except Exception as e:
        print(f"❌ Error leaving conversation: {str(e)}")

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


# API endpoints
@app.get("/api/chat/conversations")
async def get_conversations(current_user: User = Depends(get_current_user)):
    """Get list of existing conversations - optimized for bandwidth"""
    try:
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            return {"success": False, "error": "Chat service not configured"}
        
        safe_current_email = re.sub(r'[^A-Za-z0-9]', '_', current_user.email)
        
        # Get all conversation IDs where user is participant
        messages_path = f"{chat_firebase_url.rstrip('/')}/messages.json?shallow=true"
        response = requests.get(messages_path, timeout=5)
        
        conversations = []
        
        if response.status_code == 200 and response.json():
            all_conv_ids = response.json()
            print(f"📁 Found {len(all_conv_ids)} total conversations")
            
            # Filter conversations where user is participant
            for conv_id in all_conv_ids:
                if safe_current_email in conv_id:
                    print(f"👤 User is in conversation: {conv_id}")
                    
                    # Get messages for this conversation
                    conv_path = f"{chat_firebase_url.rstrip('/')}/messages/{conv_id}.json"
                    conv_response = requests.get(conv_path, timeout=5)
                    
                    if conv_response.status_code == 200 and conv_response.json():
                        messages = conv_response.json()
                        
                        # Handle both list and dict formats
                        if isinstance(messages, list) and len(messages) > 0:
                            print(f"✅ Found {len(messages)} messages in {conv_id}")
                            
                            # Extract other user from conversation ID
                            parts = conv_id.split('_')
                            other_user_safe = next((p for p in parts if p != safe_current_email), None)
                            
                            if not other_user_safe:
                                continue
                            
                            # Find actual email from messages
                            other_email = None
                            last_message = None
                            last_timestamp = None
                            unread_count = 0
                            
                            # Process messages to find details
                            for msg in messages:
                                if isinstance(msg, dict):
                                    # Get the other user's email
                                    if msg.get('f') != current_user.email:
                                        other_email = msg.get('f')
                                    elif msg.get('t') != current_user.email:
                                        other_email = msg.get('t')
                                    
                                    # Track last message
                                    last_message = msg.get('m', '')
                                    last_timestamp = msg.get('ts', '')
                                    
                                    # Count unread messages TO current user
                                    if msg.get('t') == current_user.email and not msg.get('r', False):
                                        unread_count += 1
                            
                            if not other_email:
                                print(f"⚠️ Could not find other user email in {conv_id}")
                                continue
                            
                            print(f"💬 Other user: {other_email}, Last msg: {last_message[:30]}...")
                            
                            # Get user info from MongoDB
                            other_user = users_collection.find_one(
                                {"email": other_email},
                                {"email": 1, "name": 1, "role": 1, "_id": 0}
                            )
                            
                            if other_user:
                                # Get user name
                                user_name = other_user.get("name", "")
                                if not user_name or user_name.strip() == "" or user_name == other_user["email"]:
                                    email_parts = other_user["email"].split('@')
                                    if email_parts and len(email_parts[0]) > 0:
                                        user_name = email_parts[0].replace('.', ' ').replace('_', ' ').title()
                                    else:
                                        user_name = other_user["email"]
                                
                                conversations.append({
                                    "email": other_user["email"],
                                    "name": user_name,
                                    "role": other_user.get("role", "user"),
                                    "last_message": last_message,
                                    "last_message_time": last_timestamp,
                                    "unread_count": unread_count,
                                    "online": other_user["email"] in user_sockets
                                })
                            else:
                                print(f"⚠️ User {other_email} not found in MongoDB")
                                # Still add the conversation even if user not in MongoDB
                                email_parts = other_email.split('@')
                                user_name = email_parts[0].replace('.', ' ').replace('_', ' ').title() if email_parts else other_email
                                
                                conversations.append({
                                    "email": other_email,
                                    "name": user_name,
                                    "role": "user",
                                    "last_message": last_message,
                                    "last_message_time": last_timestamp,
                                    "unread_count": unread_count,
                                    "online": other_email in user_sockets
                                })
                        else:
                            print(f"⚠️ No messages or invalid format in {conv_id}")
        else:
            print(f"📭 No conversations found in Firebase")
        
        # Sort by last message time (newest first)
        conversations.sort(key=lambda x: x.get('last_message_time', ''), reverse=True)
        
        print(f"📊 Returning {len(conversations)} conversations for {current_user.email}")
        return {"success": True, "conversations": conversations}
        
    except Exception as e:
        print(f"❌ Error getting conversations: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": True, "conversations": []}

@app.get("/api/chat/search")
async def search_users(
    q: str = Query(..., min_length=2),
    current_user: User = Depends(get_current_user)
):
    """Search for users by name or email"""
    try:
        # Search in MongoDB
        search_regex = {"$regex": q, "$options": "i"}
        users = []
        
        cursor = users_collection.find(
            {
                "$and": [
                    {"email": {"$ne": current_user.email}},
                    {"$or": [
                        {"email": search_regex},
                        {"name": search_regex}
                    ]}
                ]
            },
            {"email": 1, "name": 1, "role": 1, "_id": 0}
        ).limit(10)
        
        for user in cursor:
            # Ensure we have a proper name - fallback to email if name is empty/null
            user_name = user.get("name")
            if not user_name or user_name.strip() == "" or user_name == user["email"]:
                # Extract name from email (before @)
                email_parts = user["email"].split('@')
                if email_parts and len(email_parts[0]) > 0:
                    user_name = email_parts[0].replace('.', ' ').replace('_', ' ').title()
                else:
                    user_name = user["email"]
            
            users.append({
                "email": user["email"],
                "name": user_name,
                "role": user.get("role", "user"),
                "online": user["email"] in user_sockets
            })
        
        return {"success": True, "users": users}
        
    except Exception as e:
        print(f"Error searching users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to search users")

@app.post("/api/chat/mark_read")
async def mark_messages_read(
    data: dict,
    current_user: User = Depends(get_current_user)
):
    """Mark messages as read"""
    try:
        other_user = data.get("with")
        if not other_user:
            raise HTTPException(status_code=400, detail="Missing 'with' parameter")
        
        # Sanitize emails for Firebase path
        safe_current = re.sub(r'[^A-Za-z0-9]', '_', current_user.email)
        safe_other = re.sub(r'[^A-Za-z0-9]', '_', other_user)
        conversation_id = '_'.join(sorted([safe_current, safe_other]))
        
        # Use dedicated chat Firebase URL
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            return {"success": False, "error": "Chat service not configured"}
        
        # Get chat data
        firebase_path = f"{chat_firebase_url.rstrip('/')}/chats/{conversation_id}.json"
        response = requests.get(firebase_path, timeout=10)
        
        if response.status_code == 200 and response.json():
            chat_data = response.json()
            messages = chat_data.get('messages', [])
            
            # Update read status for messages to current user
            updated = False
            for msg_data in messages:
                if msg_data.get('t') == current_user.email and not msg_data.get('r', False):
                    msg_data['r'] = True
                    updated = True
            
            # Save back if any messages were marked as read
            if updated:
                requests.put(firebase_path, json=chat_data, timeout=10)
        
        return {"success": True}
        
    except Exception as e:
        print(f"Error marking messages as read: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to mark messages as read")

@app.get("/api/chat/users")
async def get_chat_users(current_user: User = Depends(get_current_user)):
    """Get list of users to chat with (kept for backward compatibility)"""
    try:
        # This endpoint is not used in the new version but kept for compatibility
        return {"success": True, "users": []}
        
    except Exception as e:
        print(f"Error getting chat users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get users")

# Socket.IO events
@sio.event
async def get_chat_history(sid, data):
    """Get chat history - optimized for bandwidth"""
    try:
        if sid not in connected_users:
            await sio.emit('error', {'message': 'Not authenticated'}, room=sid)
            return
        
        current_user = connected_users[sid]
        other_user = data.get('with')
        limit = data.get('limit', 50)  # Increase default limit to get more messages
        
        if not other_user:
            await sio.emit('error', {'message': 'Missing user parameter'}, room=sid)
            return
        
        print(f"📜 Loading chat history: {current_user} <-> {other_user} (limit: {limit})")
        
        # Sanitize emails for Firebase path
        safe_current = re.sub(r'[^A-Za-z0-9]', '_', current_user)
        safe_other = re.sub(r'[^A-Za-z0-9]', '_', other_user)
        conversation_id = '_'.join(sorted([safe_current, safe_other]))
        
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            await sio.emit('error', {'message': 'Chat service not configured'}, room=sid)
            return
        
        # Get all messages for this conversation
        messages_path = f"{chat_firebase_url.rstrip('/')}/messages/{conversation_id}.json"
        
        try:
            response = requests.get(messages_path, timeout=5)
            print(f"🔥 Firebase history response: {response.status_code}")
            
            sorted_messages = []
            
            if response.status_code == 200 and response.json():
                messages_array = response.json()
                
                # Convert to standard format
                if isinstance(messages_array, list):
                    print(f"📚 Found {len(messages_array)} total messages")
                    
                    for msg_data in messages_array[-limit:]:  # Get last N messages
                        if isinstance(msg_data, dict):
                            standard_msg = {
                                'id': msg_data.get('id'),
                                'from': msg_data.get('f'),
                                'to': msg_data.get('t'),
                                'message': msg_data.get('m'),
                                'timestamp': msg_data.get('ts'),
                                'read': msg_data.get('r', False),
                                'delivered': msg_data.get('d', False)
                            }
                            sorted_messages.append(standard_msg)
                    
                    print(f"💬 Sending {len(sorted_messages)} messages to client")
            else:
                print(f"📭 No messages found for conversation {conversation_id}")
                
        except Exception as e:
            print(f"❌ Firebase error: {str(e)}")
            sorted_messages = []
        
        # Send chat history to client
        await sio.emit('chat_history', {
            'with': other_user,
            'messages': sorted_messages,
            'conversation_id': conversation_id
        }, room=sid)
        
        print(f"✅ Chat history sent: {len(sorted_messages)} messages")
        
    except Exception as e:
        print(f"💥 Error in get_chat_history: {str(e)}")
        import traceback
        traceback.print_exc()
        await sio.emit('error', {'message': 'Failed to get chat history'}, room=sid)


@sio.event
async def send_message(sid, data):
    """Handle sending messages between users"""
    try:
        # Verify authentication
        if sid not in connected_users:
            print(f"❌ Unauthenticated socket {sid} trying to send message")
            await sio.emit('error', {'message': 'Not authenticated'}, room=sid)
            return
        
        sender_email = connected_users[sid]
        recipient_email = data.get('to')
        message_text = data.get('message')
        
        print(f"📨 Message attempt: {sender_email} → {recipient_email}: '{message_text}'")
        
        # Validate input
        if not recipient_email or not message_text:
            print(f"❌ Invalid input - recipient: {recipient_email}, message: {message_text}")
            await sio.emit('error', {'message': 'Missing recipient or message'}, room=sid)
            return
        
        # Use dedicated chat Firebase URL
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            print(f"❌ CHATS_FIREBASE_URL not configured")
            await sio.emit('error', {'message': 'Chat service not configured'}, room=sid)
            return
        
        # Create message
        message_id = str(uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        # Sanitize emails for Firebase path (replace @ and . with _)
        safe_sender = re.sub(r'[^A-Za-z0-9]', '_', sender_email)
        safe_recipient = re.sub(r'[^A-Za-z0-9]', '_', recipient_email)
        conversation_id = '_'.join(sorted([safe_sender, safe_recipient]))
        
        print(f"📝 Sanitized conversation ID: {conversation_id}")
        
        message_obj = {
            'id': message_id,
            'f': sender_email,  # from (shortened)
            't': recipient_email,  # to (shortened)
            'm': message_text,  # message (shortened)
            'ts': datetime.now().isoformat(),  # Use local time instead of UTC
            'r': False,  # read (shortened)
            'd': False,  # delivered (shortened)
            'ex': (datetime.now() + timedelta(hours=12)).isoformat()  # expires after 12 hours
        }
        
        print(f"💾 Saving message to Firebase: {conversation_id}/{message_id}")
        
        # Save to Firebase using optimized array structure
        try:
            # Use single path for all messages in conversation
            messages_path = f"{chat_firebase_url.rstrip('/')}/messages/{conversation_id}.json"
            
            # Get existing messages
            get_response = requests.get(messages_path, timeout=5)
            messages = get_response.json() if get_response.status_code == 200 and get_response.json() else []
            
            if not isinstance(messages, list):
                messages = []
            
            # Add new message
            messages.append(message_obj)
            
            # Keep only last 7 messages per conversation (balanced bandwidth saving)
            if len(messages) > 7:
                messages = messages[-7:]
            
            # Save messages in single operation
            response = requests.put(messages_path, json=messages, timeout=10)
            print(f"🔥 Firebase save: {response.status_code}")
            
            if response.status_code not in [200, 201]:
                await sio.emit('error', {'message': 'Failed to save message'}, room=sid)
                return
                
        except Exception as e:
            print(f"❌ Firebase error: {str(e)}")
            await sio.emit('error', {'message': 'Failed to save message'}, room=sid)
            return
        
        print(f"✅ Message saved successfully")
        
        print(f"✅ Message saved and sent successfully: {sender_email} → {recipient_email}")
        
        # Check if recipient is online
        is_delivered = recipient_email in user_sockets
        
        # Send to recipient if online
        if is_delivered:
            print(f"📤 Recipient {recipient_email} is online, delivering message")
            
            for recipient_sid in user_sockets[recipient_email]:
                await sio.emit('receive_message', {
                    'from': sender_email,
                    'message': message_text,
                    'timestamp': timestamp,
                    'id': message_id
                }, room=recipient_sid)
        else:
            print(f"📭 Recipient {recipient_email} is offline")
        
        # Clear conversations cache to force refresh
        async with chat_cache['lock']:
            chat_cache['conversations']['data'] = None
            chat_cache['conversations']['timestamp'] = None
            print("🔄 Conversations cache cleared for refresh")
        
        # Confirm to sender
        await sio.emit('message_sent', {
            'to': recipient_email,
            'message': message_text,
            'timestamp': timestamp,
            'id': message_id,
            'temp_id': data.get('temp_id'),
            'delivered': is_delivered
        }, room=sid)
        
        print(f"✅ Message sent successfully: {sender_email} → {recipient_email}")
        
    except Exception as e:
        print(f"💥 Unexpected error in send_message: {str(e)}")
        import traceback
        traceback.print_exc()
        await sio.emit('error', {'message': 'Failed to send message'}, room=sid)

@sio.event
async def mark_message_read(sid, data):
    """Mark a specific message as read and notify sender"""
    try:
        if sid not in connected_users:
            return
        
        reader_email = connected_users[sid]
        message_id = data.get('message_id')
        sender_email = data.get('from')
        
        if not message_id or not sender_email:
            return
        
        # Sanitize emails for Firebase path
        safe_reader = re.sub(r'[^A-Za-z0-9]', '_', reader_email)
        safe_sender = re.sub(r'[^A-Za-z0-9]', '_', sender_email)
        conversation_id = '_'.join(sorted([safe_reader, safe_sender]))
        
        # Use dedicated chat Firebase URL
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            return
        
        # Update read status in Firebase (optimized)
        messages_path = f"{chat_firebase_url.rstrip('/')}/messages/{conversation_id}.json"
        
        # Get messages and update read status
        get_response = requests.get(messages_path, timeout=5)
        if get_response.status_code == 200 and get_response.json():
            messages = get_response.json()
            if isinstance(messages, list):
                # Find and update the specific message
                for msg in messages:
                    if msg.get('id') == message_id:
                        msg['r'] = True
                        break
                
                # Save updated messages
                response = requests.put(messages_path, json=messages, timeout=10)
            else:
                response = None
        else:
            response = None
        
        if response.status_code in [200, 201]:
            # Notify sender if online
            if sender_email in user_sockets:
                for sender_sid in user_sockets[sender_email]:
                    await sio.emit('message_read', {
                        'message_id': message_id,
                        'reader': reader_email
                    }, room=sender_sid)
                        
    except Exception as e:
        print(f"Error marking message as read: {str(e)}")

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

# Chat page route
@app.get("/chat")
async def chat_page(request: Request, current_user: User = Depends(get_current_user)):
    """Serve the chat page"""
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": current_user
    })



#------------------------------------------------------------------------

@app.get("/settings")
async def settings_page(request: Request, current_user: User = Depends(get_current_user)):
    """Serve the settings page"""
    try:
        if not current_user:
            return RedirectResponse(url="/login", status_code=302)
        
        return templates.TemplateResponse("settings.html", {
            "request": request,
            "user": current_user
        })
        
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/login", status_code=303)
        raise e

@app.post("/logout")
async def logout():
    """Logout endpoint to clear authentication"""
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="lax"
    )
    return response

@app.get("/logout")
async def logout_get():
    """GET logout endpoint for direct navigation"""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="lax"
    )
    return response




def efficient_cleanup_firebase_messages():
    """Auto-delete messages older than 2 minutes using Firebase queries (for testing)"""
    try:
        print("🧹 Starting message cleanup (2 min expiry for testing)...")
        
        # Use dedicated chat Firebase URL
        chat_firebase_url = CHATS_FIREBASE_URL
        if not chat_firebase_url:
            print("⚠️ Skipping cleanup - no Firebase URL configured")
            return
        
        # Delete messages older than 12 hours (balanced cleanup)
        cutoff_time = (datetime.utcnow() - timedelta(hours=12)).isoformat()
        deleted_count = 0
        
        # Get all message conversations (with limit)
        messages_path = f"{chat_firebase_url.rstrip('/')}/messages.json?shallow=true"
        response = requests.get(messages_path, timeout=10)
        
        if response.status_code == 200 and response.json():
            all_conversations = response.json()
            print(f"📂 Found {len(all_conversations)} conversations to check")
            
            for conv_id, messages in all_conversations.items():
                try:
                    if not isinstance(messages, list) or not messages:
                        continue
                    
                    # Filter out expired messages
                    valid_messages = []
                    current_time = datetime.utcnow()
                    
                    for msg_data in messages:
                        if isinstance(msg_data, dict):
                            expires_at = msg_data.get('ex', '')
                            should_keep = True
                            
                            if expires_at:
                                try:
                                    expire_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                                    if current_time > expire_date:
                                        should_keep = False
                                        deleted_count += 1
                                except:
                                    pass
                            
                            if should_keep:
                                valid_messages.append(msg_data)
                    
                    # Update conversation with filtered messages or delete if empty
                    if len(valid_messages) != len(messages):
                        conv_path = f"{chat_firebase_url.rstrip('/')}/messages/{conv_id}.json"
                        if valid_messages:
                            requests.put(conv_path, json=valid_messages, timeout=10)
                        else:
                            requests.delete(conv_path, timeout=10)  # Delete empty conversation
                        print(f"🗑️ Cleaned {len(messages) - len(valid_messages)} expired messages from {conv_id}")
                                    
                except Exception as conv_error:
                    print(f"⚠️ Error processing conversation {conv_id}: {str(conv_error)}")
                    continue
        
        print(f"✅ Cleanup complete - deleted {deleted_count} expired messages")
        
    except Exception as e:
        print(f"❌ Cleanup error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    # Schedule next cleanup in 10 minutes
    Timer(600, efficient_cleanup_firebase_messages).start()  # Run every 10 minutes

# START THE CLEANUP TIMER
Timer(10, efficient_cleanup_firebase_messages).start()  # Start after 10 seconds

#lets try commit  now
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