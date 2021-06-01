from typing import Optional, Dict

from fastapi import Depends, FastAPI, HTTPException, status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel


fake_users_db: Dict = {
    "johndoe": {
        "username": "johndoe",
        "password": "secret",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "password": "secret2",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "disabled": True,
    },
}
app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


def get_user(db: Dict, token: str) -> User:
    """

    :param db:
    :param token:
    :return:
    """
    username, _, password = token.partition('$$')
    if username in db and db[username]['password'] == password:
        user_dict = db[username]
        return User(**user_dict)


def fake_decode_token(token: str) -> User:
    """

    :param token:
    :return:
    """
    # This doesn't provide any security at all
    # Check the next level
    user: User = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """

    :param token:
    :return:
    """
    user: User = fake_decode_token(token)
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

    user = User(**user_dict)
    if not user_dict['password'] == user.password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {
        "access_token": user.username + "$$" + user.password,  # $$ acts as delimiter here
        "token_type": "bearer"
    }


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> User:
    """

    :param current_user:
    :return:
    """
    return current_user
