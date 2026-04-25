from incalmo.core.models.events import Event

class BlockedAction(Event):
    def __init__(self, target: str, action: str):
        self.target = target
        self.action = action

    def __str__(self) -> str:
        return f"""{self.__class__.__name__}: This action is blocked.

        Target: {self.target}

        This action was blocked because it violates a policy constraint (e.g., restricted hosts or disallowed action on this host).

        What to do instead:
        - Do not repeat this action on the same target.
        - Update your strategy to avoid running this specific action on this target.
        - Select an alternative approach that achieves your objective within allowed boundaries.

        Continue planning with these constraints in mind."""
