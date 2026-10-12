# Secret giả trong lịch sử Git

Kiểm ngày 12/10/2026 bằng Gitleaks **8.30.1**, binary lấy từ release chính thức. Đây là token synthetic vô hiệu của đề, không phải credential thật.

- Commit: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`).
- File: `lab-fake-secret.txt:1`; rule: `lab24-synthetic-token`.
- Quét lịch sử: `gitleaks git --config .gitleaks.toml --redact --verbose --report-format json --report-path reports/gitleaks-history.json .`; phát hiện đúng **1 finding**, exit code 1 dự kiến. Bằng chứng: `reports/gitleaks-history.json` và `reports/gitleaks-history.log` (đã redact token).
- Quét hiện tại: `gitleaks dir --config .gitleaks.toml --redact --verbose .`; **0 finding**, exit code 0. Bằng chứng: `reports/gitleaks-current.log`.
- Hook `gitleaks-system` từ repo chính thức pin `rev: v8.30.1`, `pass_filenames: false`. Override `entry` sang `gitleaks dir` để kiểm toàn bộ working tree; tránh ghép nhầm subcommand `dir` vào entry mặc định `gitleaks git --staged`. Lịch sử được quét riêng, không allowlist token để che finding.
- Nếu là secret thật: thu hồi/rotate ngay tại nhà cung cấp, vô hiệu phiên liên quan, kiểm nhật ký sử dụng trái phép, cập nhật secret manager và dependency của ứng dụng; sau đó xử lý bản sao/lịch sử theo quy trình incident. Không sử dụng token đã lộ để thử xác thực.
- Xoá file khỏi HEAD không xoá secret khỏi lịch sử hoặc bản clone và không thu hồi quyền tại nhà cung cấp. Pin hook/dependency cùng hash lock giúp tái lập và phát hiện thay đổi, nhưng không thay thế rotate.

Lab giữ nguyên lịch sử để TA kiểm chứng. Không tạo credential thật, không rewrite lịch sử để xoá bằng chứng.
