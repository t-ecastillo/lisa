from dataclasses import dataclass, field
from pathlib import Path
import pathlib
from typing import Any, Callable, Dict, List, Optional, Type

from dataclasses_json import dataclass_json

from lisa import messages, notifier, schema
from lisa.combinator import Combinator
from lisa.messages import KernelBuildMessage, TestResultMessage, TestStatus
from lisa.node import Node, quick_connect
from lisa.tools.git import Git
from lisa.util import LisaException, constants, field_metadata

STOP_PATTERNS = ["first bad commit", "This means the bug has been fixed between"]


# Combinator requires a node to clone the source code.
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


# GitBisect Combinator is a loop that runs "expanded" phase
# of runbook until the bisect is complete.
# There can be any number of expanded phases, but the
# GitBisectTestResult notifier should have on boolean/None output per
# phase.


def with_remote_node(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        node = self._get_remote_node()
        ret = func(self, node, *args, **kwargs)
        node.close()
        return ret

    return wrapper


class GitBisectCombinator(Combinator):
    def __init__(
        self,
        runbook: GitBisectCombinatorSchema,
        **kwargs: Any,
    ) -> None:
        super().__init__(runbook)
        self._iteration = 0
        self._result_notifier = GitBisectResult(schema.Notifier())
        notifier.register_notifier(self._result_notifier)
        self._source_path: pathlib.PurePath

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        self._clone_source()
        if self._source_path:
            self._start_bisect()
        else:
            raise LisaException(
                "Source path is not set. Please check the source clone."
            )

    @classmethod
    def type_name(cls) -> str:
        return constants.COMBINATOR_GITBISECT

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return GitBisectCombinatorSchema

    def _next(self) -> Optional[Dict[str, Any]]:
        next: Optional[Dict[str, Any]] = None
        self._process_result()
        if not self._check_bisect_complete():
            next = {}
            next["ref"] = self._get_current_commit_hash()
        self._result_notifier.result = None
        self._iteration += 1
        return next

    def _process_result(self) -> None:
        if self._iteration == 0:
            return
        if self._result_notifier.result is not None:
            results = self._result_notifier.result
            if results:
                self._bisect_good()
            else:
                self._bisect_bad()
        else:
            raise LisaException(
                "Bisect combinator does not get result for next iteration. Please check"
                "GitBisectResult the notifier."
            )

    @with_remote_node
    def _clone_source(self, node: Node) -> None:
        # node.execute(
        #     cmd=f"mkdir -p {SOURCE_PATH}", shell=True, sudo=True, expected_exit_code=0
        # )
        # node.execute(cmd=f"chmod 777 {SOURCE_PATH}", sudo=True, expected_exit_code=0)

        git = node.tools[Git]
        self._source_path = git.clone(
            url=self.runbook.repo, cwd=node.working_path, timeout=1200
        )

    def _get_remote_node(self) -> Node:
        node = quick_connect(self.runbook.connection, "source_node")
        return node

    @with_remote_node
    def _start_bisect(self, node: Node) -> None:
        git = node.tools[Git]
        git.bisect(cwd=self._source_path, cmd="start")
        git.bisect(cwd=self._source_path, cmd=f"good {self.runbook.good_commit}")
        git.bisect(cwd=self._source_path, cmd=f"bad {self.runbook.bad_commit}")

    @with_remote_node
    def _bisect_bad(self, node: Node) -> None:
        git = node.tools[Git]
        git.bisect(cwd=self._source_path, cmd="bad")

    @with_remote_node
    def _bisect_good(self, node: Node) -> None:
        git = node.tools[Git]
        git.bisect(cwd=self._source_path, cmd="good")

    @with_remote_node
    def _check_bisect_complete(self, node: Node) -> bool:
        git = node.tools[Git]
        result = git.bisect(cwd=self._source_path, cmd="log")
        if any(pattern in result.stdout for pattern in STOP_PATTERNS):
            return True
        return False

    @with_remote_node
    def _get_current_commit_hash(self, node: Node) -> str:
        git = node.tools[Git]
        result = git.run(
            "rev-parse HEAD", cwd=self._source_path, force_run=True, shell=True
        )
        return result.stdout


class GitBisectResult(notifier.Notifier):
    @classmethod
    def type_name(cls) -> str:
        return ""

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return schema.Notifier

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        self.result: Optional[bool] = None

    def _received_message(self, message: messages.MessageBase) -> None:
        if isinstance(message, messages.TestResultMessage):
            self._update_test_result(message)
        elif isinstance(message, messages.KernelBuildMessage):
            self._update_result(message.build_sucess)
            self._update_result(message.boot_sucess)
        else:
            raise LisaException("Received unsubscribed message type")

    def _update_test_result(self, message: messages.TestResultMessage) -> None:
        if message.is_completed:
            if message.status == TestStatus.FAILED:
                self._update_result(False)
            elif message.status == TestStatus.PASSED:
                self._update_result(True)

    def _update_result(self, result: bool) -> None:
        current_result = self.result
        if current_result is not None:
            self.result = current_result and result
        else:
            self.result = result

    def _subscribed_message_type(self) -> List[Type[messages.MessageBase]]:
        return [TestResultMessage, KernelBuildMessage]
