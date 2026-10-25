# Linux Docker 빌드 식별자

`platforms/linux/package-docker-offline.sh`는 실제 Docker 빌드를 시작할 때 UTC 시각과 Git revision으로 태그를 만듭니다.

```text
koda-offline:<제품버전>-YYYYMMDDTHHMMSSZ-<git12>[-dirty]
```

같은 식별자를 Docker OCI version·created·revision 라벨, 전달물 `versions.txt`의 `docker_image`, `docker_image_tag`, `docker_image_built_at`, `git_revision`, `image-ref.txt`에 기록합니다. 설치는 이 참조를 그대로 복사합니다. 캐시된 Linux 소스가 현재 소스와 다르면 `--refresh`로 먼저 재생성해야 하며, 옛 코드를 현재 Git revision으로 표시하지 않습니다.

명시적인 태그는 기존 사용을 위해 유지합니다. `KODA_DOCKER_IMAGE_TAG`는 태그, `KODA_DOCKER_IMAGE`는 전체 출력 이미지 참조를 지정합니다. 기존 `KODA_IMAGE`도 명시적 전체 참조로 사용할 수 있습니다. override를 사용해도 실제 빌드의 OCI created 시각과 revision은 기록합니다.

Suite 전달물의 `BUILT_AT`은 묶음 생성 시각입니다. 원래 이미지 빌드 시각은 `KODA_IMAGE_BUILT_AT`, `TRACKER_IMAGE_BUILT_AT`으로 따로 전달합니다. `/opt/koda-suite/koda-suite status --prefix /opt/koda-suite`는 설치된 KODA 참조와 Tracker 태그를 표시합니다.

Tracker의 공통 태그가 바뀌는 Suite 앱 패치는 web·API·worker 이미지를 모두 새 전달물에서 검증·적재하고 관련 앱 서비스 5개를 함께 재생성합니다. 저장소 변경은 적재 전에 거절합니다. 동일 태그의 개별 패치는 기존 그룹 범위를 따르며 API 이미지 사용 worker는 함께 갱신합니다. 외부 PostgreSQL·nginx 등의 버전·digest를 날짜 태그로 재작성하지 않습니다.

## 이미 빌드된 예약 기능 이미지 묶음

`package-scheduled-patch.py --image-tag`와 별칭 `--source-image-tag`는 **존재하는 이미지의 입력 태그**입니다. 기본적으로 이 태그를 그대로 보존합니다. `--output-image-tag`는 필요한 경우 명시적으로 선택하는 패키지용 별칭이며 새 빌드가 아닙니다.

이미지 목록에는 원래 참조·Docker/OCI 생성 시각·revision·version과 별칭 여부를 보존합니다. 패키지 생성 시각은 `provenance.json`의 `packaged_at`에 별도로 기록하며 이미지 빌드 시각으로 사용하지 않습니다. 적용은 전달물의 태그를 설치 설정에 반영하고 롤백은 이전 설정과 KODA 이미지 참조를 복원합니다.

이번 검증은 Docker 명령 모의 실행과 격리된 설치 회귀를 포함합니다. 전체 운영 이미지 빌드나 레지스트리 push는 수행하지 않았습니다.
