# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
from pathlib import PurePath
from typing import Optional, Type

from assertpy.assertpy import assert_that

from lisa.executable import Tool


class Echo(Tool):
    @property
    def command(self) -> str:
        return "echo"

    @classmethod
    def _windows_tool(cls) -> Optional[Type[Tool]]:
        return WindowsEcho

    def _check_exists(self) -> bool:
        return True

    def write_to_file(
        self,
        value: str,
        file: PurePath,
        sudo: bool = False,
        timeout: int = 60,
        append: bool = False,
    ) -> None:
        # Run `echo <value> > <file>`
        operator = ">"
        if append:
            operator = ">>"
        result = self.run(
            f"'{value}' {operator} {file}",
            force_run=True,
            shell=True,
            sudo=sudo,
            timeout=timeout,
            expected_exit_code=0,
            expected_exit_code_failure_message=f"echo failed to write to {file}",
        ).stdout
        assert_that(result).does_not_contain("Permission denied")


class WindowsEcho(Echo):
    @property
    def command(self) -> str:
        return "cmd /c echo"