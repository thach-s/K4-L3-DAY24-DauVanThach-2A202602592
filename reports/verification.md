# Verification — 12/10/2026 (Asia/Bangkok)

- Linux, Python 3.13.7; venv `.venv`, pytest 9.1.1; Gitleaks **8.30.1** (binary `/tmp/lab24-tools/gitleaks`), pre-commit 4.6.2.
- `.venv/bin/python -m pytest tests/ -q`: **33 passed**, 0 fail, 0 skip (`reports/pytest.log`). Không sửa test bắt buộc.
- `.venv/bin/python -m pytest tests/test_pii.py -s -q`: gold=118, pred=118, tp=118; **precision=1.000, recall=1.000**, 2 passed (`reports/pii-metrics.log`), trên 120 dòng của bộ synthetic.
- `.venv/bin/python -m agent.check_lure 'corpus/ticket-90*.md'`: **4/4** (`reports/check-lure.log`). Hai phần 904 riêng trả None, ghép cặp được nhận diện (`reports/replay.log:5`).
- Replay riêng 4 biến thể: baseline POST thật có KH-000999; sau containment sink rỗng dưới support_l1 và dpo. Log `reports/variant-N-before.log`, `reports/variant-N-after.log` và ledger riêng mỗi principal. `reports/attack-before.log` được giữ từ runner scaffold thật trước khi sửa code.
- Sau lần pytest cuối: reset sink, replay cùng query dưới dpo, copy sink.log sang `reports/attack-after.log`: **0 byte**. Không chỉ dựa vào fixture reset của pytest.
- Ledger verify: **True**, 48 entries, tất cả reason non-empty và có on_behalf_of/agent_id/run_id/expires_at; deny http_post dpo tại dòng 23, deny read_customer support_l1 tại dòng 25. Bản sửa tool ở dòng giữa trả **False** (`reports/replay.log:7`). Không lưu PII thô trong ledger.
- Hash lock tạo bằng pip-tools 7.6.2 từ PyPI; mọi dependency được pin/hash. `.venv/bin/python -m pip install --force-reinstall --require-hashes -r requirements.lock`: **exit 0**, thực sự tải/cài lại gói để kiểm hash (`reports/lock-install.log`).
- `PATH="/tmp/lab24-tools:$PATH" PRE_COMMIT_HOME=/tmp/lab24-precommit .venv/bin/pre-commit run --all-files`: **Passed** (`reports/pre-commit.log`). Hook pin v8.30.1, quét working tree bằng dir; lịch sử quét riêng.
- Gitleaks history: **1 finding synthetic** ở commit 1bdd849, rule lab24-synthetic-token; exit 1 dự kiến. Current tree: **0 finding**, exit 0. Xem secrets-incident.md và gitleaks-*.json/log. Finding không được mô tả là credential thật.
- `git diff --check`: exit 0. Commit gốc khi bắt đầu: `52b33b5bddfcfdb5425010d6996c5c1d8eed13bd`. Các thay đổi bài làm chưa tạo commit mới; SHA để nộp lấy từ `git rev-parse HEAD` sau khi người học commit bài hoàn chỉnh.

## Lỗi setup đã gặp và cách tái hiện

Trong sandbox mặc định, `python3` thiếu pytest; `python3 -m pytest` báo No module named pytest. Tạo `.venv` rồi cài dependency đã xử lý. Lệnh pip tải package trong sandbox bị DNS Name or service not known; tạo sink localhost bị PermissionError [Errno 1] Operation not permitted. Các bước tải package/hook, bind socket và test sink đã chạy lại bằng quyền mở rộng và thành công. Lần test khi lock/report đang tạo còn 2 fail supply-chain, đã xử lý và chạy lại toàn bộ: 33 passed. Không bỏ qua hook bằng --no-verify, không đổi allowlist.

## Tái kiểm và phạm vi

```bash
source .venv/bin/activate
export PATH="/tmp/lab24-tools:$PATH"
export PRE_COMMIT_HOME=/tmp/lab24-precommit
python -m pytest tests/ -q
python -m pytest tests/test_pii.py -s -q
python -m agent.check_lure 'corpus/ticket-90*.md'
pre-commit run --all-files
python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
```

Không có lỗi chức năng còn lại theo test bắt buộc. Điều khoản pháp luật cụ thể **chưa xác minh**; nguồn chính thức, mức đối chiếu và giới hạn ghi ở compliance-mapping.md. Chưa làm bonus. Bài được AI hỗ trợ đọc yêu cầu, viết code và chạy kiểm chứng; người học cần đọc, giải thích từng control và tự chạy lại theo RULES.md trước khi nộp. Chưa push/nộp ra dịch vụ bên ngoài.
