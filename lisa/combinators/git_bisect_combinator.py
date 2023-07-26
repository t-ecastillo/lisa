from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from dataclasses_json import dataclass_json

from lisa import messages, notifier, schema
from lisa.combinator import Combinator
from lisa.tools.git import Git
from lisa.tools.mkdir import Mkdir
from lisa.util import LisaException, constants, field_metadata
from lisa.node import Node, quick_connect
from lisa.util.process import ExecutableResult
from lisa.variable import VariableEntry
from lisa.messages import KernelBuildMessage, TestResultMessage, TestStatus

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


# class BisectCache:
#     def __init__(self) -> None:
#         self.cache: List[str] = []
#         self.iteration: int = 0


class GitBisectCombinator(Combinator):
    def __init__(
        self,
        runbook: GitBisectCombinatorSchema,
        **kwargs: Any,
    ) -> None:
        super().__init__(runbook)
        # self._bisect_cache = BisectCache()
        self._result_notifier = GitBisectTestResult(schema.Notifier())
        notifier.register_notifier(self._results_collector)

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
        next: Optional[Dict[str, Any]] = None
        # If is_good is defined, it overrides test result
        # if self.runbook.is_good is not None:
        #     self._check_is_good_param()
        # else:
        self._process_result()
        if not self._check_bisect_complete():
            next = {}
            next["ref"] = self._get_current_commit_hash()
        self._result_notifier.increment_iteration()
        return next

    def _check_value_from_file(self) -> None:
        if self.runbook.is_good is not None:
            if self.runbook.is_good:
                self._bisect_good()
            else:
                self._bisect_bad()

    def _process_result(self) -> None:
        iteration = self._result_notifier.get_iteration_count()
        results = self._result_notifier.results.get(iteration)
        if results is not None:
            if results:
                self._bisect_good()
            else:
                self._bisect_bad()
        else:
            raise LisaException(f"Result missing for interation {iteration}, {results}")

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

    def _start_bisect(self) -> None:
        node = self._get_remote_node()
        git = node.tools[Git]
        git.bisect(cwd=SOURCE_PATH, cmd="start")
        git.bisect(cwd=SOURCE_PATH, cmd=f"good {self.runbook.good_commit}")
        git.bisect(cwd=SOURCE_PATH, cmd=f"bad {self.runbook.bad_commit}")

    def _bisect_bad(self) -> None:
        node = self._get_remote_node()
        git = node.tools[Git]
        git.bisect(cwd=SOURCE_PATH, cmd="bad")

    def _bisect_good(self) -> None:
        node = self._get_remote_node()
        git = node.tools[Git]
        git.bisect(cwd=SOURCE_PATH, cmd="good")

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


class GitBisectTestResult(notifier.Notifier):
    @classmethod
    def type_name(cls) -> str:
        return ""

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return schema.Notifier

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        self._iteration = 0
        self.results: Dict[int, bool] = {}
        # self.results: List[TestResultMessage] = []
        self.build_result: List[KernelBuildMessage] = []

    def increment_iteration(self) -> None:
        self._iteration += 1

    def get_iteration_count(self) -> int:
        return self._iteration

    def _received_message(self, message: messages.MessageBase) -> None:
        if isinstance(message, messages.TestResultMessage):
            self._update_test_result(message)
        elif isinstance(message, messages.KernelBuildMessage):
            self._update_result(message.build_sucess)
            self._update_result(message.boot_sucess)
        else:
            self._log.error("Received unsubscribed message type")

    def _update_test_result(self, message: messages.TestResultMessage) -> None:
        if message.is_completed:
            if message.status == TestStatus.FAILED:
                self._update_result(False)
            elif message.status == TestStatus.PASSED:
                self._update_result(True)

    def _update_result(self, result: bool) -> None:
        current_result = self.results.get(self._iteration, None)
        if current_result:
            self.results[self._iteration] = current_result and result
        else:
            self.results[self._iteration] = result

    def _subscribed_message_type(self) -> List[Type[messages.MessageBase]]:
        return [TestResultMessage, KernelBuildMessage]
