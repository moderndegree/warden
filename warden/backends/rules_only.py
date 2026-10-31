"""No decision model. Every question raises DecisionError, so warden behaves exactly as it does when a model
is down: prompt runs on rules alone, content fails closed to review, decide reports incomplete (send it to a
human). Useful for trying warden with zero services, or where no model is allowed."""
from . import DecisionError


class RulesOnly:
    def __init__(self, cfg):
        self.cfg = cfg

    def ask(self, state, questions):
        raise DecisionError("no decision model configured (backend: rules_only)")

    def health(self):
        return False
