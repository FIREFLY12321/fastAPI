from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, validator  # 添加 validator 的導入
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
import re  # 添加 re 模組用於正則表達式驗證
import json
from fastapi.responses import JSONResponse
# 12/9這邊新增登入頁
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
app = FastAPI()

# JWT 相關設置
SECRET_KEY = "your-secret-key"  # 實際應用中應使用更安全的密鑰
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_type: str
    user_id: int

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        # 先檢查電子郵件是否存在
        email_query = text("SELECT * FROM users WHERE email = :email")
        user = db.execute(email_query, {"email": form_data.username}).first()
        
        print(f"Login attempt - Email: {form_data.username}")
        print(f"User found: {user}")

        if not user:
            return JSONResponse(
                status_code=401,
                content={"status": "error", "message": "此電子郵件尚未註冊", "error_type": "email_not_found"}
            )

        # 檢查密碼
        user_dict = dict(user._mapping)
        if form_data.password != user_dict['password_hash']:
            return JSONResponse(
                status_code=401,
                content={"status": "error", "message": "密碼錯誤", "error_type": "wrong_password"}
            )

        # 登入成功
        return {
            "status": "success",
            "message": "登入成功",
            "user": {
                "user_id": user_dict['user_id'],
                "email": user_dict['email'],
                "user_type": user_dict['user_type'],
                "full_name": user_dict['full_name']
            }
        }
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": "系統錯誤", "error_type": "system_error"}
        )

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



# CORS 設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 數據庫配置
DATABASE_URL = "mysql+pymysql://root:12345678@localhost:3306/project"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 用戶模型
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: str
    user_type: str
    student_id: str

    @validator('student_id')
    def validate_student_id(cls, v):
        if not re.match(r'^[A-Za-z]\d{8}$', v):
            raise ValueError('學號格式必須為一個英文字母加上八位數字')
        return v

    @validator('email')
    def validate_email(cls, v):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):##正規表達式，檢查一個字串是否符合電子郵件地址的格式
            raise ValueError('請輸入有效的電子郵件地址')
        return v

    @validator('user_type')
    def validate_user_type(cls, v):
        if v not in ['student', 'teacher', 'admin']:
            raise ValueError('用戶類型必須是 student、teacher 或 admin')
        return v


# 在 FastAPI 代碼中添加更新用戶的模型和端點
class UserUpdate(BaseModel):
    email: str
    full_name: str
    student_id: str | None = None

    @validator('email')
    def validate_email(cls, v):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):
            raise ValueError('請輸入有效的電子郵件地址')
        return v

    @validator('student_id')
    def validate_student_id(cls, v):
        if v and not re.match(r'^[A-Za-z]\d{8}$', v):
            raise ValueError('學號格式必須為一個英文字母加上八位數字')
        return v

@app.put("/users/{user_id}")
async def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    try:
        # 檢查郵箱是否已被其他用戶使用
        query = text("SELECT 1 FROM users WHERE email = :email AND user_id != :user_id")
        result = db.execute(query, {"email": user.email, "user_id": user_id}).first()
        if result:
            raise HTTPException(status_code=400, detail="電子郵件已被使用")

        # 如果提供了學號，檢查是否已被其他用戶使用
        if user.student_id:
            query = text("SELECT 1 FROM users WHERE student_id = :student_id AND user_id != :user_id")
            result = db.execute(query, {"student_id": user.student_id, "user_id": user_id}).first()
            if result:
                raise HTTPException(status_code=400, detail="學號已被註冊")

        # 更新用戶信息
        update_query = text("""
            UPDATE users 
            SET email = :email, 
                full_name = :full_name, 
                student_id = :student_id
            WHERE user_id = :user_id
        """)
        
        result = db.execute(update_query, {
            "user_id": user_id,
            "email": user.email,
            "full_name": user.full_name,
            "student_id": user.student_id
        })
        db.commit()

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="用戶不存在")
            
        return {"message": "用戶更新成功"}
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
# POST /users/ 端點
@app.post("/users/", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # 檢查用戶名是否已存在
        query = text("SELECT 1 FROM users WHERE username = :username")
        result = db.execute(query, {"username": user.username}).first()
        if result:
            raise HTTPException(
                status_code=400,
                detail="用戶名已被註冊"
            )
        
        # 檢查電子郵件是否已存在
        query = text("SELECT 1 FROM users WHERE email = :email")
        result = db.execute(query, {"email": user.email}).first()
        if result:
            raise HTTPException(
                status_code=400,
                detail="電子郵件已被使用"
            )

        # 檢查學號是否已存在
        if user.student_id:
            query = text("SELECT 1 FROM users WHERE student_id = :student_id")
            result = db.execute(query, {"student_id": user.student_id}).first()
            if result:
                raise HTTPException(
                    status_code=400,
                    detail="學號已被註冊"
                )
        
        # 創建新用戶
        insert_query = text("""
            INSERT INTO users (username, email, password_hash, full_name, user_type, student_id)
            VALUES (:username, :email, :password, :full_name, :user_type, :student_id)
        """)
        
        params = {
            "username": user.username,
            "email": user.email,
            "password": user.password,  # 注意：實際應用中應該加密密碼
            "full_name": user.full_name,
            "user_type": user.user_type,
            "student_id": user.student_id
        }
        
        try:
            db.execute(insert_query, params)
            db.commit()
            return {"message": "用戶創建成功"}
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"數據庫錯誤: {str(e)}")
            
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        email_query = text("SELECT * FROM users WHERE email = :email")
        user = db.execute(email_query, {"email": form_data.username}).first()
        
        if not user:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "message": "此電子郵件尚未註冊",
                    "error_type": "email_not_found"
                }
            )

        user_dict = dict(user._mapping)
        if form_data.password != user_dict['password_hash']:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "message": "密碼錯誤",
                    "error_type": "wrong_password"
                }
            )

        # 生成 access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_dict['email']},
            expires_delta=access_token_expires
        )

        # 成功回傳
        return {
            "status": "success",
            "message": "登入成功",
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "user_id": user_dict['user_id'],
                "email": user_dict['email'],
                "user_type": user_dict['user_type'],
                "full_name": user_dict['full_name']
            }
        }
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "系統錯誤",
                "error_type": "system_error"
            }
        )
        
# GET /users/ 端點
@app.get("/users/")
async def read_users(db: Session = Depends(get_db)):
    query = text("SELECT * FROM users")
    result = db.execute(query).fetchall()
    return [dict(r._mapping) for r in result]

# DELETE /users/{user_id} 端點
@app.delete("/users/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    try:
        query = text("DELETE FROM users WHERE user_id = :user_id")
        result = db.execute(query, {"user_id": user_id})
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="用戶不存在")
        return {"message": "用戶刪除成功"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        
        query = text("SELECT * FROM users WHERE email = :email")
        user = db.execute(query, {"email": email}).first()
        if user is None:
            raise credentials_exception
        return dict(user._mapping)
    except JWTError:
        raise credentials_exception
@app.get("/student/courses/{email}")

#這個端點會：
    #接收學生的email作為參數
    #從數據庫中查詢該學生的所有課程信息
    #將查詢結果格式化為前端需要的格式
    #返回JSON格式的課程列表
async def get_student_courses(email: str, db: Session = Depends(get_db)):
    try:
        
        print(f"Received request for email: {email}")
        # 從 email 提取學號（假設學號是@前的部分）
        student_id = email.split('@')[0]
        print(f"Extracted student_id: {student_id}")
        # 查詢該學生的所有課程
        query = text("""
            SELECT 
                c.course_id,
                c.title,
                c.course_code,
                c.description,
                t.full_name AS teacher_name,
                ce.enrollment_date,
                CONCAT('113學年度 第 1 學期') as semester
            FROM courses c
            JOIN course_enrollments ce ON c.course_id = ce.course_id
            JOIN users s ON ce.user_id = s.user_id
            JOIN users t ON c.teacher_id = t.user_id
            WHERE s.email = :email
            ORDER BY ce.enrollment_date DESC
        """)
        #print(f"Executing query with email: {email}")                      #調適輸出
        results = db.execute(query, {"email": email}).fetchall()
        print(f"Query results: {results}")                                 #調適輸出
        # 轉換查詢結果為列表
        courses = []
        for row in results:
            course = dict(row._mapping)
            formatted_course = {
                "title": course['title'],
                "semester": course['semester'],
                "teacher": course['teacher_name'],
                "description": course['description'],
                "courseCode" : course["course_code"]
                #"enrollment_date": course['enrollment_date'].strftime("%Y-%m-%d") if course['enrollment_date'] else None
            }
            courses.append(formatted_course)
            
        # return {
        #     "status": "success",
        #     "courses": courses
        # }
         # 設置響應頭，確保正確的編碼
        return JSONResponse(#12/12更改編碼
            content={
                "status": "success"                 ,
                "courses": courses                  ,
                #"teacher": courses['teacher_name']  ,#
                #"coursCode": courses['courseCode' ] ,#

                
            },
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
            
    except Exception as e:
        print(f"Error fetching courses: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "獲取課程信息時發生錯誤",
                "error_detail": str(e)
            }
        )
#FastAPI endpoint 來獲取課程成員
@app.get("/course-members/{course_code}")
async def get_course_members(course_code: str, db: Session = Depends(get_db)):
    try:
        print(f"收到課程成員請求 - 課程代碼: {course_code}")  # 添加日誌
        
        query = text("""
            SELECT u.student_id, u.full_name
            FROM users u
            JOIN course_enrollments ce ON u.user_id = ce.user_id
            JOIN courses c ON ce.course_id = c.course_id
            WHERE c.course_code = :course_code
            AND u.user_type = 'student'
            AND ce.status = 'active'
            ORDER BY u.student_id
        """)
        
        result = db.execute(query, {"course_code": course_code}).fetchall()
        print(f"查詢結果: {result}")  # 添加日誌
        
        members = [
            {
                "student_id": row.student_id,
                "full_name": row.full_name
            }
            for row in result
        ]
        print(f"格式化後的成員數據: {members}")  # 添加日誌
        
        return {
            "status": "success",
            "members": members
        }
        
    except Exception as e:
        print(f"錯誤詳情: {str(e)}")  # 添加詳細錯誤信息
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"獲取課程成員時發生錯誤: {str(e)}"  # 返回具體錯誤信息
            }
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("fastAPI:app", host="192.168.196.159", port=8000, reload=True)