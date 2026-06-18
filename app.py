import json
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy import (
    create_engine,
    String,
    Float,
    ForeignKey,
    select
)

from sqlalchemy.orm import (
    DeclarativeBase,
    sessionmaker,
    Mapped,
    mapped_column,
    Session
)

import bcrypt
import jwt
import json
from datetime import datetime, timedelta

# ==========================================
# FASTAPI APP
# ==========================================

app = FastAPI()

templates = Jinja2Templates(directory="Frontend")

# ==========================================
# JWT SETTINGS
# ==========================================

SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ==========================================
# DATABASE SETUP
# ==========================================

engine = create_engine(
    "sqlite:///expense_tracker.db",
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# ==========================================
# BASE CLASS
# ==========================================

class Base(DeclarativeBase):
    pass

# ==========================================
# USER TABLE
# ==========================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(String(50))

    email: Mapped[str] = mapped_column(
        String(100),
        unique=True
    )

    hashed_password: Mapped[str] = mapped_column(
        String(255)
    )

# ==========================================
# EXPENSE TABLE
# ==========================================

class Expense(Base):
    __tablename__ = "expenses"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    category: Mapped[str] = mapped_column(
        String(50)
    )

    amount: Mapped[float] = mapped_column(
        Float
    )

    description: Mapped[str] = mapped_column(
        String(200)
    )

    date: Mapped[str] = mapped_column(
        String(20)
    )

# ==========================================
# BUDGET TABLE
# ==========================================

class Budget(Base):
    __tablename__ = "budgets"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    monthly_budget: Mapped[float] = mapped_column(
        Float
    )

# ==========================================
# CREATE TABLES
# ==========================================

Base.metadata.create_all(bind=engine)

# ==========================================
# PASSWORD HASHING
# ==========================================

def get_password_hash(password):

    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(
    plain_password,
    hashed_password
):

    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )

# ==========================================
# JWT TOKEN
# ==========================================

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update(
        {"exp": expire}
    )

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

# ==========================================
# DATABASE DEPENDENCY
# ==========================================

def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()

# ==========================================
# CURRENT USER
# ==========================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):

    token = request.cookies.get(
        "access_token"
    )

    if not token:
        return None

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            return None

    except:

        return None

    user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    return user        

# ==========================================
# HOME ROUTE
# ==========================================

@app.get("/")
def home(
    current_user: User = Depends(get_current_user)
):

    if current_user:
        return RedirectResponse(
            url="/dashboard",
            status_code=303
        )

    return RedirectResponse(
        url="/login",
        status_code=303
    )

# ==========================================
# SIGNUP PAGE
# ==========================================

@app.get(
    "/signup",
    response_class=HTMLResponse
)
def signup_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="signup.html"
    )

# ==========================================
# SIGNUP SUBMIT
# ==========================================

@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    existing_user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    if existing_user:

        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error": "Email already registered"
            }
        )

    new_user = User(
        name=name,
        email=email,
        hashed_password=get_password_hash(password)
    )

    db.add(new_user)

    db.commit()

    return RedirectResponse(
        url="/login",
        status_code=303
    )

# ==========================================
# LOGIN PAGE
# ==========================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
def login_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )


# ==========================================
# LOGIN SUBMIT
# ==========================================

@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = db.scalars(
        select(User).where(
            User.email == email
        )
    ).first()

    if not user:

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid Email or Password"
            }
        )

    if not verify_password(
        password,
        user.hashed_password
    ):

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid Email or Password"
            }
        )

    access_token = create_access_token(
        data={
            "sub": user.email
        }
    )

    response = RedirectResponse(
        url="/dashboard",
        status_code=303
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True
    )

    return response

# ==========================================
# LOGOUT
# ==========================================

@app.get("/logout")
def logout():

    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    response.delete_cookie(
        "access_token"
    )

    return response

# ==========================================
# DASHBOARD
# ==========================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard(
    request: Request,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db)
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expenses = db.scalars(
        select(Expense).where(
            Expense.user_id == current_user.id
        )
    ).all()
    category_totals = {}
    for expense in expenses:
        if expense.category not in category_totals:
            category_totals[expense.category] = 0
            
        category_totals[expense.category] += expense.amount

    chart_labels = list(category_totals.keys())
    chart_values = list(category_totals.values())

    total_expense = sum(
        expense.amount
        for expense in expenses
    )

    budget_record = db.scalars(
        select(Budget).where(
            Budget.user_id == current_user.id
        )
    ).first()

    budget = (
        budget_record.monthly_budget
        if budget_record
        else 0
    )

    remaining = budget - total_expense

    recent_expenses = expenses[-5:]

    return templates.TemplateResponse(
    request=request,
    name="dashboard.html",
    context={
        "current_user": current_user,
        "total_expense": total_expense,
        "budget": budget,
        "remaining": remaining,
        "recent_expenses": recent_expenses,

        "chart_labels": json.dumps(chart_labels),
        "chart_values": json.dumps(chart_values)
    }
)

# ==========================================
# VIEW EXPENSES
# ==========================================

@app.get(
    "/expenses",
    response_class=HTMLResponse
)
def view_expenses(
    request: Request,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db)
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expenses = db.scalars(
        select(Expense).where(
            Expense.user_id == current_user.id
        )
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="expenses.html",
        context={
            "expenses": expenses
        }
    )

# ==========================================
# ADD EXPENSE PAGE
# ==========================================

@app.get(
    "/add-expense",
    response_class=HTMLResponse
)
def add_expense_page(
    request: Request,
    current_user: User = Depends(
        get_current_user
    )
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="add_expense.html"
    )


# ==========================================
# ADD EXPENSE
# ==========================================

@app.post("/add-expense")
def add_expense(
    category: str = Form(...),
    amount: float = Form(...),
    description: str = Form(...),
    date: str = Form(...),

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = Expense(
        user_id=current_user.id,
        category=category,
        amount=amount,
        description=description,
        date=date
    )

    db.add(expense)

    db.commit()

    return RedirectResponse(
        url="/expenses",
        status_code=303
    )

# ==========================================
# UPDATE EXPENSE PAGE
# ==========================================

@app.get(
    "/update-expense/{expense_id}",
    response_class=HTMLResponse
)
def update_expense_page(
    expense_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )
    if not expense or expense.user_id != current_user.id:
        return RedirectResponse(
        url="/expenses",
        status_code=303
    )
    

    return templates.TemplateResponse(
        request=request,
        name="update_expense.html",
        context={
            "expense": expense
        }
    )


# ==========================================
# UPDATE EXPENSE
# ==========================================

@app.post(
    "/update-expense/{expense_id}"
)
def update_expense(
    expense_id: int,
    category: str = Form(...),
    amount: float = Form(...),
    description: str = Form(...),
    date: str = Form(...),

    current_user: User = Depends(get_current_user),

    db: Session = Depends(get_db)
):

    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )
    if not expense or expense.user_id != current_user.id:
        return RedirectResponse(
        url="/expenses",
        status_code=303
    )

    if expense:

        expense.category = category
        expense.amount = amount
        expense.description = description
        expense.date = date

        db.commit()

    return RedirectResponse(
        url="/expenses",
        status_code=303
    )


# ==========================================
# DELETE EXPENSE
# ==========================================

@app.get(
    "/delete-expense/{expense_id}"
)
def delete_expense(
    expense_id: int,

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    if not current_user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    expense = db.get(
        Expense,
        expense_id
    )
    if not expense or expense.user_id != current_user.id:
        return RedirectResponse(
        url="/expenses",
        status_code=303
    )

    if expense:

        db.delete(expense)

        db.commit()

    return RedirectResponse(
        url="/expenses",
        status_code=303
    )

# ==========================================
# BUDGET PAGE
# ==========================================

@app.get(
    "/budget",
    response_class=HTMLResponse
)
def budget_page(
    request: Request,
    current_user: User = Depends(
        get_current_user
    )
):

    if not current_user:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="budget.html"
    )


# ==========================================
# SAVE BUDGET
# ==========================================

@app.post("/budget")
def save_budget(
    monthly_budget: float = Form(...),

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    budget = db.scalars(
        select(Budget).where(
            Budget.user_id == current_user.id
        )
    ).first()

    if budget:

        budget.monthly_budget = monthly_budget

    else:

        budget = Budget(
            user_id=current_user.id,
            monthly_budget=monthly_budget
        )

        db.add(budget)

    db.commit()

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )