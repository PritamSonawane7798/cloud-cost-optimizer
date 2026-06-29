from pathlib import Path
import pytest

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


@pytest.fixture(scope="session")
def aws_csv():
    return SAMPLES / "aws_cur_sample.csv"


@pytest.fixture(scope="session")
def azure_csv():
    return SAMPLES / "azure_cost_sample.csv"


@pytest.fixture(scope="session")
def azure_json():
    return SAMPLES / "azure_cost_sample.json"
