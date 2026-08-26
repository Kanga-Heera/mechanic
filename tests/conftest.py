from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def rules_mixed_dir() -> Path:
    return FIXTURES / "rules_mixed"


@pytest.fixture
def rules_categories_dir() -> Path:
    return FIXTURES / "rules_categories"
