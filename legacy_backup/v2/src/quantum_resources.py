import enum

class ResourceStatus(enum.Enum):
    UNUSED = 1
    CONSUMED = 2

class ResourceType(enum.Enum):
    AUTH_PAIR = 1
    TELEPORT_PAIR = 2

class QuantumResourceError(Exception):
    pass

class BellPairResource:
    def __init__(self, session_id: str, pair_id: int, resource_type: ResourceType):
        self.session_id = session_id
        self.pair_id = pair_id
        self.resource_type = resource_type
        self.status = ResourceStatus.UNUSED
        
    def consume(self):
        if self.status == ResourceStatus.CONSUMED:
            raise QuantumResourceError(f"Bell pair {self.pair_id} for session {self.session_id} is already consumed.")
        self.status = ResourceStatus.CONSUMED

class SessionResourceManager:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.resources = {}
        
    def allocate_pairs(self, count: int, resource_type: ResourceType):
        start_id = len(self.resources)
        for i in range(count):
            self.resources[start_id + i] = BellPairResource(self.session_id, start_id + i, resource_type)
            
    def get_resource(self, pair_id: int) -> BellPairResource:
        if pair_id not in self.resources:
            raise QuantumResourceError(f"Resource {pair_id} not found in session {self.session_id}")
        return self.resources[pair_id]
        
    def consume_resource(self, pair_id: int):
        resource = self.get_resource(pair_id)
        resource.consume()
