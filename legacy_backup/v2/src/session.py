import enum
import uuid

class SessionState(enum.Enum):
    IDLE = 1
    INITIALIZING = 2
    ACTIVE = 3
    VERIFYING = 4
    TERMINATED = 5

class SessionError(Exception):
    pass

class Session:
    def __init__(self):
        self.session_id = None
        self.state = SessionState.IDLE
        self.challenge = None
        self.current_sequence_number = 0
        self.consumed_sequences = set()
    
    def start_session(self, challenge: str):
        if self.state != SessionState.IDLE and self.state != SessionState.TERMINATED:
            raise SessionError(f"Cannot start session from state {self.state.name}")
        self.session_id = str(uuid.uuid4())
        self.state = SessionState.INITIALIZING
        self.challenge = challenge
        self.current_sequence_number = 0
        self.consumed_sequences = set()
    
    def activate(self):
        if self.state != SessionState.INITIALIZING:
            raise SessionError(f"Cannot activate session from state {self.state.name}")
        self.state = SessionState.ACTIVE

    def start_verification(self):
        if self.state != SessionState.ACTIVE:
            raise SessionError(f"Cannot start verification from state {self.state.name}")
        self.state = SessionState.VERIFYING
    
    def end_verification_and_resume(self):
        if self.state != SessionState.VERIFYING:
            raise SessionError(f"Cannot resume session from state {self.state.name}")
        self.state = SessionState.ACTIVE

    def terminate(self):
        self.state = SessionState.TERMINATED
        
    def consume_sequence(self, sequence_number: int):
        if sequence_number in self.consumed_sequences:
            raise SessionError("DUPLICATE_SEQUENCE")
        self.consumed_sequences.add(sequence_number)

    def get_next_sequence_number(self) -> int:
        self.current_sequence_number += 1
        return self.current_sequence_number
