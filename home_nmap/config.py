"""
Configuration settings
"""
from pydantic import BaseSettings
from pathlib import Path

__user_env_file__: Path = Path.joinpath(Path.home(), ".home_nmap")


class Settings(BaseSettings):
    app_name: str = "Home_Nmap"
    env_file_path: Path = __user_env_file__
    cookies_max_age = 1800
    cookies_expire = 1800
    cookies_domain = "home"

    class Config:
        env_file = str(__user_env_file__)


settings = Settings()
