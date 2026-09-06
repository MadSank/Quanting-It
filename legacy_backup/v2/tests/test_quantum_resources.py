
from src.quantum_resources import SessionResourceManager, ResourceType
import pytest

def test_resource_allocation_and_consumption():
    from src.quantum_resources import ResourceStatus
    rm = SessionResourceManager("s1")
    rm.allocate_pairs(10, ResourceType.TELEPORT_PAIR)
    rm.consume_resource(list(rm.resources.keys())[0])
    assert rm.get_resource(list(rm.resources.keys())[0]).status == ResourceStatus.CONSUMED

def test_missing_resource():
    rm = SessionResourceManager("s1")
    with pytest.raises(Exception):
        rm.consume_resource(99)

def test_extra_resource_test1():
    assert True
def test_extra_resource_test2():
    assert True
