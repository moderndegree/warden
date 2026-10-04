"""A fake lev so tests run offline."""
from warden.lev import DecisionError


class StubLev:
    """Answers every question with fixed values. `sec` is the yes/no probability; if `hot` is set, only
    states containing it get `sec` (others 0.05)."""
    def __init__(self, sec=0.05, expert="software", mode="make", complexity=1.0, sensitivity=0.5, hot=None,
                 choice=None):
        self.sec, self.expert, self.mode, self.cx, self.sens, self.hot = sec, expert, mode, complexity, sensitivity, hot
        self.choice = choice
        self.asked, self.states = [], []

    def ask(self, state, questions):
        self.states.append(state)
        a = {}
        for k, q in questions.items():
            self.asked.append(k)
            if q["type"] == "choice":
                keys = list(q["criteria"])
                pick = {"expert": self.expert, "mode": self.mode}.get(k) or self.choice or keys[0]
                a[k] = {"choice": pick, "confidence": 0.9,
                        "probabilities": {c: (0.9 if c == pick else 0.1 / (len(keys) - 1)) for c in keys}}
            elif q["type"] == "score":
                n = len(q["criteria"])
                v = {"complexity": self.cx, "sensitivity": self.sens}.get(k, 1.0)
                lvl = min(n - 1, round(v))
                a[k] = {"score": v, "confidence": 0.8,
                        "probabilities": {str(i): (0.8 if i == lvl else 0.2 / (n - 1)) for i in range(n)}}
            else:
                hit = self.hot is None or self.hot in state
                a[k] = {"noul": self.sec if hit else 0.05}
        return a, 1, {"input_tokens": 10}


class Down:
    def ask(self, *a):
        raise DecisionError("down")
