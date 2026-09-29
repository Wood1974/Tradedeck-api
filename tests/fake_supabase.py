"""
In-memory mock Supabase client for testing.
"""


class FakeSupabaseClient:
    """Mock Supabase client for testing. Stores tables in-memory.

    Note: Very limited mock. Filters are not applied.
    Use only for basic insert operations.
    """

    def __init__(self):
        """Initialize with empty table store."""
        self._tables = {}

    def table(self, table_name):
        """Return a table query builder."""
        if table_name not in self._tables:
            self._tables[table_name] = {}
        return FakeTableQuery(self._tables[table_name])


class FakeTableQuery:
    """Mock table query builder for in-memory operations."""

    def __init__(self, data):
        self._data = data
        self._filters = []

    def select(self, *args, **kwargs):
        """Select operation (returns self for chaining)."""
        return self

    def insert(self, record):
        """Insert a record (returns self for chaining)."""
        # Simulate insert and store for later retrieval in execute()
        self._data[record.get('id')] = record
        self._inserted_record = record
        return self

    def eq(self, column, value):
        """Filter by equality."""
        self._filters.append(('eq', column, value))
        return self

    def execute(self):
        """Execute the query."""
        # Return inserted record if available, otherwise empty result
        if hasattr(self, '_inserted_record'):
            return FakeQueryResult([self._inserted_record])
        # For testing purposes, return empty result
        return FakeQueryResult([])

    def limit(self, n):
        """Limit results."""
        return self


class FakeQueryResult:
    """Mock query result."""

    def __init__(self, data):
        self.data = data
        self.count = len(data)
