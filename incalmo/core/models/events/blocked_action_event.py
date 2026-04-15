from incalmo.core.models.events import Event

class BlockedAction(Event):
    def __init__(self, target: str, action: str):
        self.target = target
        self.action = action

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: The Action {self.action} is not allowed on the targets with prefix IP {self.target}"
