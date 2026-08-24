import pytest
from unittest.mock import MagicMock, patch
import speakeasy
import speakeasy.config as cfg
from strilight.engine.core import AnalyzerCore


@pytest.fixture(autouse=True)
def mock_speakeasy_fixture():
    with patch.object(speakeasy, 'Speakeasy', create=True) as mock_se_cls:
        mock_se = MagicMock()
        mock_se_cls.return_value = mock_se
        mock_module = MagicMock()
        mock_module.base = 0x1000
        mock_module.image_size = 0x2000
        mock_se.load_module.return_value = mock_module
        mock_se.load_shellcode.return_value = mock_module
        yield mock_se_cls, mock_se


def test_analyzer_core_init(mock_speakeasy_fixture):
    mock_se_cls, mock_se = mock_speakeasy_fixture
    core = AnalyzerCore(target_path=["dummy.exe", "arg1"])
    
    assert mock_se_cls.called
    mock_se.load_module.assert_called_with("dummy.exe")
    assert core.module_base == 0x1000
    assert core.module_size == 0x2000
    assert core.tick_counter == 0
    assert core.current_mem_reads == []
    assert core.current_mem_writes == []


def test_analyzer_core_init_shellcode(mock_speakeasy_fixture):
    mock_se_cls, mock_se = mock_speakeasy_fixture
    mock_module = MagicMock()
    mock_module.base = 0x1000
    mock_module.image_size = 0x100
    mock_se.load_shellcode.return_value = mock_module

    code = b"\x90\x90"
    core = AnalyzerCore(code=code, arch="x8664")
    
    mock_se.load_shellcode.assert_called_with(code, arch='amd64')


def test_get_memory_permissions_hash():
    core = AnalyzerCore(target_path=["dummy.exe"])
    core.se = MagicMock()
    
    core.se.emu.mem_regions.return_value = [
        (0x1000, 0x2000, 7),
        (0x2000, 0x3000, 3)
    ]
    
    hash_val = core.get_memory_permissions_hash()
    assert isinstance(hash_val, str)
    assert len(hash_val) == 32  # md5 hash length


def test_start():
    core = AnalyzerCore(target_path=["dummy.exe"])
    core.se = MagicMock()
    
    core.start()
    core.se.run_module.assert_called_once_with(core.module)
