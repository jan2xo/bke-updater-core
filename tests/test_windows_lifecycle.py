import pytest

from bke_updater_core.helper.main import _wait_for_exit_windows, wait_for_exit


class FakeKernel32:
    def __init__(self, *, handle=7, wait_result=0):
        self.handle = handle
        self.wait_result = wait_result
        self.open_calls = []
        self.wait_calls = []
        self.closed = []

    def OpenProcess(self, access, inherit, pid):
        self.open_calls.append((access, inherit, pid))
        return self.handle

    def WaitForSingleObject(self, handle, milliseconds):
        self.wait_calls.append((handle, milliseconds))
        return self.wait_result

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 1


def test_windows_wait_uses_process_handle_and_closes_it():
    api = FakeKernel32()

    _wait_for_exit_windows(4321, 2.5, kernel32=api)

    assert api.open_calls == [(0x00100000, False, 4321)]
    assert api.wait_calls == [(7, 2500)]
    assert api.closed == [7]


def test_windows_wait_times_out_fail_closed():
    api = FakeKernel32(wait_result=0x00000102)

    with pytest.raises(TimeoutError, match="did not exit"):
        _wait_for_exit_windows(4321, 0.01, kernel32=api)

    assert api.closed == [7]


def test_windows_wait_rejects_unknown_wait_result():
    api = FakeKernel32(wait_result=0xFFFFFFFF)

    with pytest.raises(OSError, match="WaitForSingleObject"):
        _wait_for_exit_windows(4321, 1.0, kernel32=api)

    assert api.closed == [7]


def test_missing_process_handle_is_treated_as_already_exited():
    api = FakeKernel32(handle=0)
    _wait_for_exit_windows(4321, 1.0, kernel32=api)
    assert api.wait_calls == []
    assert api.closed == []


def test_wait_pid_must_be_positive():
    with pytest.raises(ValueError, match="positive"):
        wait_for_exit(0)
