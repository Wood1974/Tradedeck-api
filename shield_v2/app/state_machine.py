from __future__ import annotations
from dataclasses import dataclass
STATES={"challenge_issued","capture_received","verified","sealed","amended","voided","rejected"}
TRANSITIONS={"challenge_issued":{"capture_received","rejected"},"capture_received":{"verified","rejected"},"verified":{"sealed","rejected"},"sealed":{"amended","voided"},"amended":{"voided"},"voided":set(),"rejected":set()}
@dataclass(frozen=True)
class EvidenceStateMachine:
    state:str
    def can_transition(self,target:str)->bool:return self.state in STATES and target in STATES and target in TRANSITIONS[self.state]
    def transition(self,target:str)->"EvidenceStateMachine":
        if not self.can_transition(target):raise ValueError(f"illegal_evidence_transition:{self.state}->{target}")
        return EvidenceStateMachine(target)
