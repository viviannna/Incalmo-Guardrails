from incalmo.core.models.events import Event

class BlockedFn(Event):
    def __init__(self, command: str, target: str):
        self.target = target
        self.command = command

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: The command {self.command} is not allowed on the targets with prefix IP {self.target}"
