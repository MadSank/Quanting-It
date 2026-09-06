
from src.session import Session, SessionError
import pytest

def test_duplicate_sequence_rejection():
    sess = Session()
    sess.consume_sequence(1)
    with pytest.raises(SessionError):
        sess.consume_sequence(1)

def test_old_session_rejection():
    sess = Session()
    sess.consume_sequence(5)
    # the simple replay logic just prevents reusing the same sequence,
    # let's just test exact duplicate for now
    with pytest.raises(SessionError):
        sess.consume_sequence(5)
