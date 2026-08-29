# KODA Linux 오프라인 배포

Linux x86_64 서버에서 인터넷 연결 없이 KODA를 설치하고 Java 아카이브를
점검하는 절차입니다. Docker 없이 사용자 소유 경로에 설치하는 tarball을
기준으로 하며, Python 3.10 이상이 필요합니다.

## 빌드와 설치

인터넷에 연결된 승인된 빌드 PC에서 패키지를 만든 뒤 결과물만 반입합니다.

```bash
bash platforms/linux/package-offline.sh --refresh
tar -xzf dist/linux/koda-linux-x86_64-<version>.tar.gz
cd koda-linux-x86_64-<version>
bash install.sh
```

설치 스크립트는 번들된 Syft, Grype, Grype DB, NVD/CISA 자료와 Chromium을
사용합니다. 실행 중 자동 다운로드나 외부 통신은 하지 않습니다.

## Java 아카이브 점검

```bash
/home/user0/koda/koda jar-scan \
  --target /deploy/apps \
  --target /deploy/worker-apps \
  --output-dir reports/java-scan \
  --fail-on high --fail-on-kev
```

HTML과 Markdown은 현재 한국어로 생성되며 `--language`는 `ko`만 지원합니다.
`Final`은 현재 번들 Grype DB 기준으로 취약점이 없는
것을 확인한 최종 조치 후보입니다.

소스 취약점은 `koda scan --target /deploy/source --format html --output reports/source.html`로
메인과 `source-detail.html`을 생성합니다. Java 아카이브는 위 `jar-scan` 명령으로
라이브러리 메인·상세 HTML 두 파일을 생성합니다.
`--target`을 반복하면 여러 배포 폴더의 아카이브·컴포넌트·취약점·SBOM을 중복 제거하여
하나의 라이브러리 메인/상세 리포트로 통합합니다.

자세한 전달물 비교와 Windows 데이터 패키지는
[폐쇄망 배포 개요](../../docs/install/offline-delivery.md)를 참고하세요.

## KODA + KODA SBOM Tracker 통합 포털

서버에서 로그인·계정·역할·분석 회차 화면이 필요하면 단독 tarball 대신
[통합 폐쇄망 설치본](suite/README.md)을 사용합니다. 통합본은 Tracker 계정과
로그아웃 세션을 공유하고 KODA 권한은 별도로 관리하며, KODA의 8765 포트를
호스트에 공개하지 않습니다.

- [한국어 문서 인덱스](../../docs/README.md)
