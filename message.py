from dataclasses import dataclass
from datetime import datetime
from user import User


@dataclass
class Message:
    text: str
    client: User
    time: datetime

    def __str__(self):
        return f'"{self.text}"'
