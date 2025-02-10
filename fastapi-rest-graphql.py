from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import Session, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import strawberry
from strawberry.fastapi import GraphQLRouter
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import uvicorn
from typing import List
from pydantic import BaseModel

DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    posts = relationship("Post", back_populates="owner")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")
    
    def as_dict(self):
        return {"title": self.title, "content": self.content}
    
class PostResponse(BaseModel):
    id: int
    title: str
    content: str

    class Config:
        orm_mode = True  # This tells Pydantic to treat the SQLAlchemy model as a dictionary

Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.post("/register")
def register(username: str, password: str, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(password)
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created"}

@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/posts", response_model=List[PostResponse])
def get_posts(db: Session = Depends(get_db)):
    return db.query(Post).all()

@app.post("/posts")
def create_post(title: str, content: str, owner_id: int, db: Session = Depends(get_db)):
    post = Post(title=title, content=content, owner_id=owner_id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post

@strawberry.type
class PostType:
    id: int
    title: str
    content: str
    owner_id: int
    
@strawberry.type
class Query:
    @strawberry.field
    def posts(self, info) -> List[PostType]:
        db: Session = info.context["db"]
        posts = db.query(Post).all()
        return [PostType(id=post.id, title=post.title, content=post.content) for post in posts]

def get_context():
    return {"db": SessionLocal()}

graphql_app = GraphQLRouter(strawberry.Schema(query=Query), context_getter=get_context)
app.include_router(graphql_app, prefix="/graphql")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
