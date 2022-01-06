from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    text: str
    client: object
    time: datetime
