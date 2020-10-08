class TenantError(Exception):
    pass

class MultipleTenantError(TenantError):
    def __init__(self, connections):
        self.connections = connections

class InvalidTenantError(TenantError):
    pass


