# Compliance mapping — bằng chứng kỹ thuật, không chứng nhận pháp lý

Đối chiếu nguồn ngày **12/10/2026**. Xác minh tên/số văn bản và nguồn chính thức; **chưa xác minh điều khoản cụ thể trong văn bản gốc**. Các control dưới đây là liên hệ kỹ thuật của bài lab, không kết luận đáp ứng nghĩa vụ pháp luật.

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160&typegroup=) | Giảm PII ở context/output; giới hạn mục đích và chặn restricted egress | `agent/pii.py:45`, `agent/runner.py:119`, `agent/policy.py:64`, `reports/ledger.jsonl:23` | Điều khoản cụ thể: **chưa xác minh**; dữ liệu synthetic, chưa xử lý consent/quyền chủ thể/retention production |
| [NĐ 356/2025/NĐ-CP — chi tiết và biện pháp thi hành Luật Bảo vệ dữ liệu cá nhân](https://chinhphu.vn/?docid=216387&pageid=27160) | Ghi decision có reason; DPIA-lite và incident note | `agent/ledger.py:52`, `reports/dpia-lite.md:1`, `reports/secrets-incident.md:1` | Điều khoản cụ thể: **chưa xác minh**; DPIA-lite không thay hồ sơ pháp lý đầy đủ |
| [Luật AI 134/2025/QH15 — Trí tuệ nhân tạo](https://congbao.chinhphu.vn/van-ban/luat-so-134-2025-qh15-468694/61695.htm) | Giới hạn agent bằng scope, purpose, TTL và split | `agent/policy.py:69`, `agent/policy.py:82`, `agent/runner.py:126` | Điều khoản cụ thể: **chưa xác minh**; mock deterministic, không chứng minh độ an toàn mọi model |
| OWASP ASI01 — Agent Goal Hijack | Free text chỉ ở A; B suy customer từ metadata tin cậy | `agent/runner.py:120`, `agent/runner.py:143`, `tests/test_split.py:98`, `reports/replay.log:1` | Trust boundary ở mức code; cùng process, không chống mapping đã bị chiếm quyền |
| OWASP ASI03 — Identity & Privilege Abuse | Quyền hiệu lực giao principal/agent/parent, purpose và TTL; support deny trước đọc | `agent/policy.py:75`, `agent/policy.py:82`, `agent/runner.py:131`, `tests/test_obo.py:45`, `reports/ledger.jsonl:25` | `--as` là giả lập; production cần xác thực và delegation token có kiểm chứng |
| OWASP ASI04 — Agentic Supply Chain Vulnerabilities | Hash lock, hook pin v8.30.1 và scanner lịch sử | `requirements.lock:7`, `.pre-commit-config.yaml:3`, `reports/gitleaks-history.json:3`, `reports/pre-commit.log:2` | Scanner phát hiện token giả, không chứng minh mọi dependency an toàn; pin không thay rotate |

Nguồn OWASP chính thức: [Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) và [GenAI Crosswalk](https://genai-security-project.github.io/crosswalk/). Tên ASI01/03/04 theo taxonomy Agentic Top 10 2026, không trộn với số thứ tự LLM Top 10.

Ledger mô phỏng tamper-evident chỉ trong chuỗi quan sát được; không gọi là immutable. Bằng chứng sửa dòng: `reports/replay.log:7`. `reports/attack-after.log` rỗng nên không có số dòng để viện dẫn; đối chiếu kích thước 0 byte tại `reports/replay.log:8`.
