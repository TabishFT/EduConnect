from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from imagekitio import ImageKit
import base64
from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
import io
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
async def read_index():
    return FileResponse("static/getstarted.html")

@app.get("/login", include_in_schema=True)
@app.head("/login", include_in_schema=True)
async def login_page():
    return FileResponse("static/index.html")

@app.get("/select_role", include_in_schema=True)
@app.head("/select_role", include_in_schema=True)
async def select_role_page(request: Request):
    try:
        current_user = await get_current_user(request)
        if current_user.role:
            return RedirectResponse(url="/home", status_code=303)
        return FileResponse("static/select_role.html")
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



@app.get("/intern_profile")
async def intern_profile_page(request: Request):
    try:
        current_user = await get_current_user(request)
        # Allow access if role is being set via localStorage
        if current_user.role not in ["intern", None]:
            raise HTTPException(status_code=403, detail="Access denied")
        return FileResponse("static/intern_profile.html")
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
        return FileResponse("static/startup_profile.html")
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
        
        # यहां 'intern' रोल को भी स्वीकार करें
        if current_user.role not in ['startup', 'intern']:
            return RedirectResponse(url="/select_role", status_code=303)
        
        # Return role info for API requests
        return JSONResponse(
            content={"role": current_user.role},
            status_code=200
        )
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

@app.get("/preview", response_class=FileResponse)
async def intern_preview_page():
    return FileResponse("static/preview.html")

@app.get("/preview2", response_class=FileResponse)
async def startup_preview_page():
    return FileResponse("static/preview2.html")

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
            # Existing user, redirect based on role
            redirect_url = "/home" if db_user_data.get("role") else "/select_role"

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

@app.get("/{full_path:path}")
async def handle_external_links(full_path: str):
    # Remove domain check and directly prepend https://
    return RedirectResponse(f"https://{full_path}")


#imagekit:
imagekit = ImageKit(
    private_key=os.getenv("IMAGEKIT_PRIVATE_KEY"),
    public_key=os.getenv("IMAGEKIT_PUBLIC_KEY"),
    url_endpoint="https://ik.imagekit.io/iupyun2hd"
)


# @app.post("/upload")
# async def upload_file(file: UploadFile = File(...)):
#     try:
#         contents = await file.read()
#         print(f"Uploading: {file.filename}, Size: {len(contents)} bytes")

#         # Convert to Base64
#         encoded_string = base64.b64encode(contents).decode("utf-8")
#         data_url = f"data:application/pdf;base64,{encoded_string}"

#         # Upload using base64 string to preserve file as-is
#         result = imagekit.upload(
#             file=data_url,
#             file_name=file.filename,
#             options=UploadFileRequestOptions(
#                 folder="/uploads/",
#                 is_private_file=False,
#                 tags=["pdf", "upload"],
#                 use_unique_file_name=False,
#                 overwrite_file=True  # ✅ Add this line
# )

#         )

#         if result and hasattr(result, 'response_metadata') and result.response_metadata:
#             return {
#                 "url": result.response_metadata.raw['url'],
#                 "name": file.filename
#             }
#         else:
#             return JSONResponse(content={"error": "ImageKit upload failed"}, status_code=500)

#     except Exception as e:
#         print(f"Upload failed: {str(e)}")
#         return JSONResponse(content={"error": str(e)}, status_code=500)
#Tabish Ansari






@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    try:
        # Sanitize email
        raw_email = current_user.email
        safe = re.sub(r"[^A-Za-z0-9]", "_", raw_email)
        
        # Get file extension
        ext = file.filename.split(".")[-1].lower()
        
        # Determine file type
        if ext in ("jpg", "jpeg", "png", "gif", "webp"):
            base = f"{safe}_profile"
        else:
            base = f"{safe}_resume"
            
        final_filename = f"{base}.{ext}"
        
        # Read file contents
        contents = await file.read()
        
        # Upload to ImageKit
        result = imagekit.upload(
            file=contents,  # Pass bytes directly
            file_name=final_filename,
            options=UploadFileRequestOptions(
                folder="/uploads/",
                use_unique_file_name=False,
                is_private_file=False
            )
        )
        
        # Debug: Print full response
        print(f"ImageKit response: {result}")
        
        # Extract URL from response
        if result and hasattr(result, 'url') and result.url:
            return {
                "url": result.url,
                "name": final_filename
            }
        else:
            error_msg = "ImageKit upload failed"
            if hasattr(result, 'error'):
                error_msg = result.error
            return JSONResponse(
                content={"error": error_msg},
                status_code=500
            )
            
    except Exception as e:
        print(f"Upload failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)






if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        proxy_headers=True,
        forwarded_allow_ips="*"
    )
