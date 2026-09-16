# Linux 오프라인 업데이트 패치 (2026-09-16)

리비전 `20260916-limits1`은 폐쇄망 서버 디렉터리 점검의 대용량 JSON·파일 목록 경로를 확장합니다. KODA 예약 API JSON은 500MiB, 대상은 최대 20만 파일·4GiB·24시간, 직접 업로드는 2GiB, 압축 해제는 40만 파일·4GiB입니다. Tracker SBOM 업로드는 500MiB이며 Nginx는 multipart 여유를 포함해 501MiB, KODA 업로드 경로는 2049MiB를 허용합니다.

단일 원격 목록 행, 경로 이탈, 압축 폭탄, 파일 수·해제 용량 검증은 그대로 유지합니다. 기존 설치의 `UPLOAD_MAX_BYTES=104857600`만 500MiB로 이관하고 별도 운영자 설정은 보존합니다. `KODA_JSON_MAX_BYTES`가 없으면 500MiB를 추가합니다.

## 폐쇄망 적용

```bash
sha256sum -c koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz.sha256
tar -xzf koda-scheduled-offline-patch-x86_64-20260916-limits1.tar.gz
cd koda-scheduled-offline-patch-x86_64-20260916-limits1
sha256sum -c manifest.sha256
python3 preflight.py --prefix /home/user0/koda-suite
bash apply.sh --prefix /home/user0/koda-suite
```

적용 전에 SQLite·PostgreSQL, 기존 이미지, Tracker Compose·gateway·`.env`를 백업합니다. 기존 named volume과 입력 데이터는 삭제하지 않습니다. 실패하거나 검증 결과가 맞지 않으면 서비스를 정지한 뒤 복원합니다.

```bash
bash rollback.sh --prefix /home/user0/koda-suite
```

## 적용 후 확인

```bash
grep -E '^(UPLOAD_MAX_BYTES|KODA_JSON_MAX_BYTES)=' /home/user0/koda-suite/tracker/.env
docker exec koda-sbom-gateway nginx -T | grep client_max_body_size
/home/user0/koda-suite/koda-suite status --prefix /home/user0/koda-suite
```

예약 점검은 먼저 작은 디렉터리로 완료 상태를 확인한 뒤 실제 대형 디렉터리를 실행합니다. 운영 서버의 메모리·디스크 사용량과 처리 시간을 함께 기록해야 실제 폐쇄망 수용 검증이 완료됩니다.

Grype DB와 Tracker vuln-data는 이미지와 별개로 업로드·검증·적용·롤백할 수 있습니다. 이 패키지는 최신화 기능을 포함하지만 이번 빌드에서 외부 취약점 피드를 새로 내려받지는 않습니다.
