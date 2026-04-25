from incalmo.core.models.events import Event

class BlockedFn(Event):
    def __init__(self, command: str, target: str):
        self.target = target
        self.command = command

    def __str__(self) -> str:
        return f"""{self.__class__.__name__}: This command is blocked.

        Target: {self.target}

        This command was blocked because it violates a policy constraint (e.g., restricted hosts or disallowed command on this host).

        What to do instead:
        - Do not repeat this action on the same target.
        - Update your strategy to avoid running this specific action on this target.
        - Select an alternative approach that achieves your objective within allowed boundaries.

        Continue planning with these constraints in mind."""