"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agent import ledger, pii, policy, tools

# No document text, attacker customer ID or attacker URL is accepted by Run B.
_TICKET_FILE = re.compile(r"ticket-(\d+)(?:b)?\.md")
_SINK_URL = "http://127.0.0.1:10024/reconcile"


class ToolBoundary:
    def __init__(self, principal_id, run_name, scopes, ledger_path):
        self.principal_id = principal_id
        self.agent_id = "lab24-agent/" + run_name
        self.run_id = str(uuid4())
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        self.scopes = scopes
        self.ledger_path = ledger_path

    def authorize(self, tool, args, classification, purpose, egress=False):
        context = policy.PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner=self.agent_id, delegation_depth=0, egress_enabled=egress,
            principal_id=self.principal_id, requested_tool=tool,
            agent_scopes=self.scopes, parent_scopes=(), expires_at=self.expires_at,
        )
        allowed, reason = policy.check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(), "agent_id": self.agent_id,
            "run_id": self.run_id, "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at, "tool": tool,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest(),
            "classification": classification, "decision": "allow" if allowed else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allowed


def _run_a(message, llm, boundary) -> tuple[list[int], str]:
    if not boundary.authorize("search_docs", {"query": message}, "internal", "summarize-tickets"):
        return [], "Yêu cầu bị từ chối theo quyền principal mô phỏng."
    docs = tools.search_docs(message)
    # Inspect attacks locally; their fields are never used to select private data.
    llm.find_injection("\n\n".join(doc["text"] for doc in docs))
    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    ids = sorted({int(match.group(1)) for doc in safe_docs
                  if (match := _TICKET_FILE.fullmatch(doc["id"]))})
    # Redact output too. Only this user-facing summary and typed IDs leave A.
    return ids, pii.redact(llm.summarize(safe_docs))


def _run_b(ticket_ids: list[int], boundary) -> None:
    if not ticket_ids:
        return
    if any(type(ticket) is not int or ticket <= 0 for ticket in ticket_ids):
        raise ValueError("Run B accepts positive integer ticket IDs only")
    # Check OBO BEFORE even opening the private fixture for metadata mapping.
    context = policy.PolicyContext(
        "restricted", "support-reply", boundary.agent_id, 0, False,
        boundary.principal_id, "read_customer", boundary.scopes, (), boundary.expires_at,
    )
    authorized, _ = policy.check(context)
    if not authorized:
        boundary.authorize("read_customer", {"ticket_ids": ticket_ids}, "restricted", "support-reply")
        return
    selected = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    # Trusted metadata is the sole source of customer IDs.
    customer_ids = sorted({row["customer_id"] for row in customers
                           if selected.intersection(row.get("related_tickets", []))})
    del customers
    records = []
    for customer_id in customer_ids:
        if boundary.authorize("read_customer", {"customer_id": customer_id}, "restricted", "support-reply"):
            records.append(tools.read_customer(customer_id))
    # A fixed local reconciliation proposal demonstrates the PEP independently
    # of injection recognition. B never receives an attacker-selected endpoint.
    if records:
        args = {"url": _SINK_URL, "body": {"records": records}}
        if boundary.authorize("http_post", args, "restricted", "support-reply", egress=True):
            tools.http_post(args["url"], args["body"])


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir or REPORTS_DIR) / "ledger.jsonl"
    a = ToolBoundary(principal_id, "run-a", ("search_docs",), ledger_path)
    b = ToolBoundary(principal_id, "run-b", ("read_customer", "http_post"), ledger_path)
    ticket_ids, summary = _run_a(message, llm, a)
    _run_b(ticket_ids, b)
    return summary
