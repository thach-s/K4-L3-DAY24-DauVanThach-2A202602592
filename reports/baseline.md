# Baseline

1. `_naive_loop()` trong `agent/loop.py:27` không tạo `agent_id`, `run_id`, TTL hay kiểm principal; `run_once()` chọn baseline khi gặp scaffold ban đầu nên `--as` chưa cưỡng chế quyền ở đường này.
2. `_naive_loop()` lấy chỉ thị từ toàn văn `search_docs`, gọi `read_customer` rồi `http_post` trực tiếp (`agent/loop.py:39`, `agent/loop.py:44`); chỉ có allowlist localhost trong `agent/tools.py`, không có PEP cho phép theo identity/mục đích/phân loại.
3. `reports/attack-before.log:1` là POST thật vào `/reconcile` có hồ sơ synthetic `KH-000999` (CCCD `811753472374`, SĐT `0861707895`, STK `9103069783`), do handler `sink/sink.py:40` ghi lại và được lưu trước khi triển khai runner.
