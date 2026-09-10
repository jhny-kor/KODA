# 서버·GitLab 예약 설정 확장 검증 (2026-09-09)

작업 위치: `security-batch` Git worktree. 원본 `security` 작업 파일은 변경하지 않았습니다.

## 구현

- 관리자 → 연동 설정 → 서버·GitLab 스케줄 점검에서 대상별 실행 시각과 반복 주기를 저장합니다.
- 한국시간 기준 매일, 선택 요일, 1·2·3·4·6·8·12·24시간 간격을 지원합니다.
- GitLab 연결 저장소의 브랜치/태그와 하위 디렉터리 또는 원격 서버 디렉터리를 선택합니다.
- 기존 대상의 매일 01:00 설정을 유지하며, 기존 DB에 새 컬럼을 추가합니다.
- 실행 슬롯을 영속 저장하여 중복을 방지하고, 대기 작업이 있으면 먼저 처리합니다. 새로 저장/수정한 시각 이전의 예약은 소급 실행하지 않습니다.
- GitLab 토큰은 포털에 유지합니다. 임대한 작업만 고정 커밋의 원본 아카이브를 내부 API로 스트리밍할 수 있습니다. 임의 저장소로 변경 요청은 차단합니다.
- GitLab 변경분은 파일 해시로 비교합니다. 결과 저장 뒤 원본 아카이브·추출본·분석 복사본을 모두 정리하는 기존 흐름을 사용합니다.
- GitLab 전체 아카이브에 수집/압축 해제 크기 제한을 적용합니다. 분석은 지정 디렉터리로 제한합니다. LFS 객체와 서브모듈 내용은 수집하지 않습니다.
- Tracker는 기존 스케줄 결과 인터페이스를 재사용하므로 이번 확장에 추가 변경은 없습니다.

## 검증 결과

- 기존 Linux portal 수동/GitLab/관리 API 회귀: 65개 통과.
- 호스트 스케줄 관련 테스트: 65개 중 61개 통과, Linux 전용 4개 제외.
- Linux amd64 컨테이너에서 현재 소스를 read-only mount, 외부 네트워크 차단 후 스케줄 테스트: 65개 중 64개 통과. Node 없는 실행 이미지의 JS 구문 검사 1개 제외.
- 실제 headless Chromium: GitLab 태그/주간 예약 저장과 재편집, 원격 서버 4시간 예약 저장, API 재조회 확인. 브라우저 스크립트 오류 없음.
- 내부 HTTP API를 통한 GitLab 수집 → 실제 분석 → 결과 저장 → 원본 삭제 확인. GitLab upstream은 테스트 archive로 대체했습니다.
- 동일 내용/다른 commit timestamp의 GitLab 재점검에서 변경 0건 확인.
- 잘못된 lease와 임의 저장소 지정 차단, 403/404 영구 오류와 429/503 재시도 분류 확인.
- Python compileall, JavaScript 구문 검사, git diff --check 통과.

재실행:

```sh
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p 'test_schedule*.py' -q
PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests -p 'test_linux_portal.py' -q
```

## 배포 경계

실제 운영 GitLab/SSH 서버를 연결하거나 운영 컨테이너를 교체하지 않았습니다.
기존 `koda-scheduled-offline-patch-x86_64-20260908.tar.gz`와 이미지에는 이번 소스 변경을 재포장하지 않았습니다.
테스트 중 출력된 임시 패키지 경로/체크섬은 패키징 단위 테스트 산출물이며 배포본이 아닙니다.
