from typing import Optional, Dict

from fastapi import Depends, FastAPI, HTTPException, status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

fake_users_db: Dict = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()


def fake_hash_password(password: str) -> str:
    """

    :param password:
    :return:
    """
    return "fakehashed" + password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def get_user(db: Dict, username: str) -> UserInDB:
    """

    :param db:
    :param username:
    :return:
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token: str) -> UserInDB:
    """

    :param token:
    :return:
    """
    # This doesn't provide any security at all
    # Check the next level
    user: UserInDB = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """

    :param token:
    :return:
    """
    user: UserInDB = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Dict:
    """

    :param form_data:
    :return:
    """
    user_dict = fake_users_db.get(form_data.username)

    if not user_dict:

        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {
        "access_token": user.username,
        "token_type": "bearer"
    }


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> User:
    """

    :param current_user:
    :return:
    """
    return current_user
