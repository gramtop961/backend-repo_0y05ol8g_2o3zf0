"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import date as DateType, datetime

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    password_hash: str = Field(..., description="Salted password hash 'salt:hash'")
    is_active: bool = Field(True, description="Whether user is active")
    role: str = Field("user", description="User role: user|admin")

class Session(BaseModel):
    """Active sessions tokens for auth"""
    user_id: str = Field(...)
    token: str = Field(...)
    expires_at: datetime = Field(...)

class MenuItem(BaseModel):
    """
    Daily menu items
    Collection name: "menuitem"
    """
    day: DateType = Field(..., description="Menu date (YYYY-MM-DD)")
    title: str = Field(..., description="Dish name")
    description: Optional[str] = Field(None, description="Short description")
    price: float = Field(..., ge=0, description="Price")
    available: bool = Field(True, description="Is available today")

class OrderItem(BaseModel):
    item_id: str
    title: str
    price: float
    quantity: int = Field(..., ge=1)

class Order(BaseModel):
    """Orders collection"""
    user_id: str
    day: DateType
    items: List[OrderItem]
    total: float = Field(..., ge=0)
    status: str = Field("new", description="new|preparing|ready|completed|cancelled")
