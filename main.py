import os
from datetime import datetime, timedelta, date as DateType
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson.objectid import ObjectId
import hashlib, hmac, secrets

from database import db, create_document
from schemas import User, MenuItem, Order, OrderItem

app = FastAPI()

# CORS: we use Authorization header (no cookies), so we can safely allow all origins without credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Helpers

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100_000).hex()
    return f"{salt}:{pwd_hash}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, stored = password_hash.split(":", 1)
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100_000).hex()
        return hmac.compare_digest(check, stored)
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


# Pydantic request models
class RegisterDTO(BaseModel):
    name: str
    email: str
    password: str


class LoginDTO(BaseModel):
    email: str
    password: str


class CreateMenuItemDTO(BaseModel):
    day: DateType
    title: str
    description: Optional[str] = None
    price: float
    available: bool = True
    category: Optional[str] = None


class CreateOrderDTO(BaseModel):
    items: List[OrderItem]


class SetRoleDTO(BaseModel):
    email: str
    role: str  # expected values: 'user' | 'admin'


class SetRoleByIdDTO(BaseModel):
    user_id: str
    role: str  # expected values: 'user' | 'admin'


# Auth dependency
async def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ", 1)[1]
    session = db["session"].find_one({"token": token, "expires_at": {"$gt": datetime.utcnow()}})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db["user"].find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "user")}


@app.get("/")
def root():
    return {"message": "Lunch menu API running"}


# Auth endpoints
@app.post("/auth/register")
def register(dto: RegisterDTO):
    if db["user"].find_one({"email": dto.email}):
        raise HTTPException(status_code=400, detail="User already exists")
    password_hash = hash_password(dto.password)
    user = User(name=dto.name, email=dto.email, password_hash=password_hash, is_active=True, role="user")
    user_id = create_document("user", user)
    return {"id": user_id, "name": user.name, "email": user.email}


@app.post("/auth/login")
def login(dto: LoginDTO):
    user = db["user"].find_one({"email": dto.email})
    if not user or not verify_password(dto.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = new_token()
    expires_at = datetime.utcnow() + timedelta(days=7)
    db["session"].insert_one({"user_id": str(user["_id"]), "token": token, "expires_at": expires_at})
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "user")}}


@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        db["session"].delete_one({"token": token})
    return {"ok": True}


# One-time setup endpoints to set a user's role using a secret header token
@app.post("/admin/setup/set-role")
def set_user_role(dto: SetRoleDTO, x_setup_token: Optional[str] = Header(default=None)):
    setup_token = os.getenv("ADMIN_SETUP_TOKEN", "")
    if not setup_token or not x_setup_token or x_setup_token != setup_token:
        raise HTTPException(status_code=403, detail="Forbidden")
    user = db["user"].find_one({"email": dto.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"role": dto.role}})
    return {"ok": True, "email": dto.email, "role": dto.role}


@app.post("/admin/setup/set-role-by-id")
def set_user_role_by_id(dto: SetRoleByIdDTO, x_setup_token: Optional[str] = Header(default=None)):
    setup_token = os.getenv("ADMIN_SETUP_TOKEN", "")
    if not setup_token or not x_setup_token or x_setup_token != setup_token:
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        oid = ObjectId(dto.user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    user = db["user"].find_one({"_id": oid})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db["user"].update_one({"_id": oid}, {"$set": {"role": dto.role}})
    return {"ok": True, "user_id": dto.user_id, "role": dto.role}


# Menu endpoints
@app.get("/menu/today")
def get_today_menu(category: Optional[str] = Query(default=None)):
    today = datetime.utcnow().date().isoformat()
    query = {"day": today, "available": True}
    if category:
        query["category"] = category
    items = list(db["menuitem"].find(query))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.post("/menu")
def create_menu_item(dto: CreateMenuItemDTO, user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can add menu items")
    item = MenuItem(**dto.model_dump())
    item_id = create_document("menuitem", item)
    return {"id": item_id}


@app.get("/menu")
def list_menu(day: Optional[str] = Query(default=None), category: Optional[str] = Query(default=None)):
    query = {}
    if day:
        query["day"] = day
    if category:
        query["category"] = category
    items = list(db["menuitem"].find(query).sort("day", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Orders
@app.post("/orders")
def create_order(dto: CreateOrderDTO, user=Depends(get_current_user)):
    today = datetime.utcnow().date()
    total = sum(i.price * i.quantity for i in dto.items)
    order = Order(user_id=user["id"], day=today, items=dto.items, total=total, status="new")
    order_id = create_document("order", order)
    return {"id": order_id, "total": total}


@app.get("/orders/me")
def my_orders(user=Depends(get_current_user)):
    orders = list(db["order"].find({"user_id": user["id"]}).sort("created_at", -1))
    for o in orders:
        o["id"] = str(o.pop("_id"))
    return orders


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        from database import db as _db
        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = _db.name if hasattr(_db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except ImportError:
        response["database"] = "❌ Database module not found"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
