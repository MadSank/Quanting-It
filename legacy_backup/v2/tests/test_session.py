
from src.session import Session, SessionState, SessionError
import pytest

def test_session_initialization():
    sess = Session()
    assert sess.state == SessionState.IDLE

def test_valid_transitions():
    sess = Session()
    sess.start_session("chal")
    sess.activate()
    assert sess.state == SessionState.ACTIVE
    sess.start_verification()
    assert sess.state == SessionState.VERIFYING
    sess.terminate()
    assert sess.state == SessionState.TERMINATED

def test_invalid_transitions():
    sess = Session()
    with pytest.raises(SessionError):
        sess.activate()
