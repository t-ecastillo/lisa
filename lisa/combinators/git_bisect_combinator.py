from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from dataclasses_json import dataclass_json

from lisa import schema
from lisa.combinator import Combinator
from lisa.tools.git import Git
from lisa.tools.mkdir import Mkdir
from lisa.util import constants, field_metadata
from lisa.node import Node, quick_connect
from lisa.util.process import ExecutableResult
from lisa.variable import VariableEntry

SOURCE_PATH = Path("/mnt/code")
STOP_PATTERNS = ["first bad commit", "This means the bug has been fixed between"]


@dataclass_json()
@dataclass
class GitBisectCombinatorSchema(schema.Combinator):
    connection: Optional[schema.RemoteNode] = field(
        default=None, metadata=field_metadata(required=True)
    )
    repo: str = field(
        default="",
        metadata=field_metadata(
            required=True,
        ),
    )
    good_commit: str = field(
        default="",
        metadata=field_metadata(
            required=True,
        ),
    )
    bad_commit: str = field(
        default="",
        metadata=field_metadata(
            required=True,
        ),
    )


class GitBisectCombinator(Combinator):
    def __init__(self, runbook: GitBisectCombinatorSchema) -> None:
        super().__init__(runbook)
        # assert runbook.connection, "connection must be defined."
        # assert runbook.repo, "source repo must be defined."
        # assert runbook.good_commit, "good commit must be defined."
        # assert runbook.bad_commit, "bad commit must be defined."
        self._git_bisect_cache: List[str] = []

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        # self._validate_node()
        self._clone_source()
        self._start_bisect()

    @classmethod
    def type_name(cls) -> str:
        return constants.COMBINATOR_GITBISECT

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return GitBisectCombinatorSchema

    def _next(self) -> Optional[Dict[str, Any]]:
        result: Optional[Dict[str, Any]] = None
        if not self._check_bisect_complete():
            result = {}
            result["ref"] = self._get_current_commit_hash()
        return result

    # def _validate_node(self) -> None:
    #     node = self._get_remote_node()
    #     assert node.test_connection(), "connection to remote node failed."
    #     node.close()
    #     node.tools[Git]

    def _clone_source(self) -> None:
        node = self._get_remote_node()
        node.execute(
            cmd=f"mkdir -p {SOURCE_PATH}", shell=True, sudo=True, expected_exit_code=0
        )
        node.execute(cmd=f"chmod 777 {SOURCE_PATH}", sudo=True, expected_exit_code=0)

        git = node.tools[Git]
        git.clone(url=self.runbook.repo, cwd=SOURCE_PATH, dir_name=".", timeout=1200)

    def _get_remote_node(self) -> Node:
        node = quick_connect(self.runbook.connection, "source_node")
        return node

    # def _recover_bisect(self) -> None:
    #     self._start_bisect()
    #     node = self._get_remote_node()
    #     git = node.tools[Git]
    #     for state in self._git_bisect_cache:
    #         git.bisect(SOURCE_PATH, state)

    def _start_bisect(self) -> None:
        node = self._get_remote_node()
        git = node.tools[Git]
        git.bisect(cwd=SOURCE_PATH, cmd="start")
        git.bisect(cwd=SOURCE_PATH, cmd=f"good {self.runbook.good_commit}")
        git.bisect(cwd=SOURCE_PATH, cmd=f"bad {self.runbook.bad_commit}")

    def _check_bisect_complete(self) -> bool:
        node = self._get_remote_node()
        git = node.tools[Git]
        result = git.bisect(cwd=SOURCE_PATH, cmd="log")
        if any(pattern in result.stdout for pattern in STOP_PATTERNS):
            return True
        return False

    def _get_current_commit_hash(self) -> str:
        node = self._get_remote_node()
        git = node.tools[Git]
        result = git.run("rev-parse HEAD", cwd=SOURCE_PATH, force_run=True, shell=True)
        return result.stdout
