from bson import ObjectId
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url
import cloudinary
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.voting_app
users_collection = db.users
candidates_collection = db.candidates
votes_collection = db.votes
positions_collection = db.positions

# Cloudinary Setup
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# JWT Setup
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Pydantic Models
class User(BaseModel):
    username: str
    email: str
    is_admin: bool = False


class UserInDB(User):
    hashed_password: str


class Candidate(BaseModel):
    id: Optional[str] = Field(None, alias="_id")  # This will map MongoDB's "_id" to "id"
    name: str
    position: str
    image_url: Optional[str] = None

    class Config:
        allow_population_by_field_name = True
        json_encoders = {ObjectId: str}


class Vote(BaseModel):
    user_id: str
    candidate_id: str
    position: str


class Position(BaseModel):
    name: str


class Token(BaseModel):
    access_token: str
    token_type: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = users_collection.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    user["_id"] = str(user["_id"])  # Convert ObjectId to string
    return user


async def get_current_admin(token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# Routes
@app.post("/register")
async def register(username: str, email: str, password: str, is_admin: bool = False):
    if users_collection.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    user = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "is_admin": is_admin
    }
    users_collection.insert_one(user)
    return {"msg": "User registered successfully"}


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def get_current_user_details(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "is_admin": current_user["is_admin"]
    }

@app.post("/positions")
async def create_position(position: Position, current_user: dict = Depends(get_current_admin)):
    if positions_collection.find_one({"name": position.name}):
        raise HTTPException(status_code=400, detail="Position already exists")
    positions_collection.insert_one(position.dict())
    return {"msg": "Position created successfully"}


@app.post("/candidates")
async def create_candidate(name: str, position: str, image: UploadFile = File(...),
                           current_user: dict = Depends(get_current_admin)):
    if not positions_collection.find_one({"name": position}):
        raise HTTPException(status_code=400, detail="Position does not exist")

    # Upload image to Cloudinary
    upload_result = upload(image.file)
    image_url = upload_result["secure_url"]

    candidate = {
        "name": name,
        "position": position,
        "image_url": image_url
    }
    result = candidates_collection.insert_one(candidate)
    return {"msg": "Candidate created successfully", "candidate_id": str(result.inserted_id)}


@app.get("/positions", response_model=List[Position])
async def get_positions():
    positions = list(positions_collection.find({}, {"_id": 0}))
    return positions

@app.get("/candidates", response_model=List[Candidate])
async def get_candidates():
    candidates = list(candidates_collection.find())
    # Convert ObjectId to string and format response
    return [
        {
            "_id": str(candidate["_id"]),
            "name": candidate["name"],
            "position": candidate["position"],
            "image_url": candidate.get("image_url")
        }
        for candidate in candidates
    ]


@app.get("/candidates/{candidate_id}", response_model=Candidate)
async def get_candidate_by_id(candidate_id: str):
    if not ObjectId.is_valid(candidate_id):
        raise HTTPException(status_code=400, detail="Invalid candidate ID format")

    candidate = candidates_collection.find_one({"_id": ObjectId(candidate_id)})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    return {
        "_id": str(candidate["_id"]),
        "name": candidate["name"],
        "position": candidate["position"],
        "image_url": candidate.get("image_url")
    }


@app.get("/candidates/position/{position_name}", response_model=List[Candidate])
async def get_candidates_by_position(position_name: str):
    # First check if the position exists
    if not positions_collection.find_one({"name": position_name}):
        raise HTTPException(status_code=404, detail="Position not found")

    candidates = list(candidates_collection.find({"position": position_name}))

    return [
        {
            "_id": str(candidate["_id"]),
            "name": candidate["name"],
            "position": candidate["position"],
            "image_url": candidate.get("image_url")
        }
        for candidate in candidates
    ]


@app.delete("/candidates/{candidate_id}")
async def delete_candidate(candidate_id: str, current_user: dict = Depends(get_current_admin)):
    # Validate candidate_id format
    if not ObjectId.is_valid(candidate_id):
        raise HTTPException(status_code=400, detail="Invalid candidate ID format")

    # Check if candidate exists
    candidate = candidates_collection.find_one({"_id": ObjectId(candidate_id)})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    # Delete all votes for this candidate
    votes_collection.delete_many({"candidate_id": candidate_id})

    # Delete the candidate
    result = candidates_collection.delete_one({"_id": ObjectId(candidate_id)})

    if result.deleted_count == 1:
        return {"msg": "Candidate deleted successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete candidate")


@app.post("/vote")
async def vote(candidate_id: str, position: str, current_user: dict = Depends(get_current_user)):
    # Validate candidate_id and position
    if not candidates_collection.find_one({"_id": ObjectId(candidate_id), "position": position}):
        raise HTTPException(status_code=400, detail="Invalid candidate or position")

    if votes_collection.find_one({"user_id": str(current_user["_id"]), "position": position}):
        raise HTTPException(status_code=400, detail="Already voted for this position")

    vote = {
        "user_id": str(current_user["_id"]),
        "candidate_id": candidate_id,
        "position": position,
        "timestamp": datetime.utcnow()
    }
    votes_collection.insert_one(vote)
    return {"msg": "Vote recorded successfully"}

@app.get("/results")
async def get_results():
    results = {}
    positions = positions_collection.find()
    for pos in positions:
        position_name = pos["name"]
        candidates = candidates_collection.find({"position": position_name})
        candidate_results = []
        for candidate in candidates:
            vote_count = votes_collection.count_documents({"candidate_id": str(candidate["_id"])})
            candidate_results.append({
                "name": candidate["name"],
                "votes": vote_count,
                "image_url": candidate.get("image_url")
            })
        results[position_name] = candidate_results
    return results