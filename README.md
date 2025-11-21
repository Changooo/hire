# AID - Agent Isolation via eBPF

eBPF LSM을 이용한 AI Agent 파일 접근 제어 시스템

## 사전 요구사항

### 1. 커널 요구사항
- Linux 커널 5.7 이상
- **중요**: 커널에서 LSM BPF가 활성화되어야 함
  ```bash
  # 확인 방법
  grep CONFIG_BPF_LSM /boot/config-$(uname -r)
  # CONFIG_BPF_LSM=y 이어야 함 (현재: CONFIG_BPF_LSM is not set ❌)

  cat /sys/kernel/security/lsm
  # "bpf"가 포함되어야 함
  ```

### 2. 빌드 도구
```bash
sudo apt-get install -y clang libbpf-dev linux-headers-$(uname -r)
```

### 3. 권한
- **root 권한** 필요 (sudo 또는 root 계정)

## 빌드

```bash
make clean
make
```

빌드 결과:
- `bpf/aid_lsm.bpf.o` - eBPF 프로그램
- `src/aid_lsm_loader` - BPF 로더
- `src/addagent` - 에이전트 등록 도구

## 사용 방법

### Step 1: eBPF LSM 프로그램 로드 (시스템 부팅 후 1회)

```bash
sudo ./src/aid_lsm_loader
```

이 명령은:
- eBPF 프로그램을 커널에 로드
- BPF 맵을 `/sys/fs/bpf/aid_inode_policies`에 pin
- 프로그램 종료 후에도 BPF는 커널에 계속 상주

**성공 메시지**: `[aid_lsm_loader] aid LSM BPF 로드 완료.`

### Step 2: manifest.yaml 작성

에이전트의 파일 접근 권한을 정의합니다.

```yaml
# example_manifest.yaml
agentname: myagent
permissions:
  files:
    - path: /tmp/test.txt
      read: true
      write: false
    - path: /home/user/data/*.json
      read: true
      write: true
    - path: /etc/passwd
      read: false
      write: false
```

**주의**: glob 패턴(`*`)을 사용하면 **현재 존재하는 파일만** 등록됩니다.

### Step 3: 에이전트 등록

```bash
sudo ./src/addagent example_manifest.yaml
```

이 명령은:
1. 시스템 계정 생성: `agent_myagent` (UID 50000~59999 범위)
2. manifest의 파일들을 stat()하여 inode 정보 수집
3. BPF 맵에 (inode + uid → 권한) 등록

**성공 메시지**:
```
[addagent] useradd 실행: useradd -r -M -s /usr/sbin/nologin -u 50000 agent_myagent
[addagent] agent user 'agent_myagent' uid=50000 생성
[addagent] uid=50000 dev=... ino=... read=1 write=0 등록
[addagent] 완료.
```

### Step 4: 에이전트로 명령 실행

```bash
# 테스트 파일 생성
echo "secret data" > /tmp/test.txt

# 읽기 시도 (성공해야 함)
sudo -u agent_myagent cat /tmp/test.txt

# 쓰기 시도 (실패해야 함 - Permission denied)
sudo -u agent_myagent sh -c 'echo "hack" > /tmp/test.txt'
```

## 작동 원리

```
1. 파일 열기 시도 (open, fopen 등)
          ↓
2. 커널 LSM 훅: file_open 발동
          ↓
3. eBPF 프로그램 실행 (aid_lsm.bpf.c)
          ↓
4. 호출자 UID 확인 (50000~59999 범위인가?)
          ↓
5. BPF 맵 조회: (inode + uid) → 권한
          ↓
6. 허용/거부 결정
   - 정책 있음 + 권한 부족 → -EACCES (Permission denied)
   - 정책 없음 → 허용 (fail-open)
   - 정책 있음 + 권한 충분 → 허용
```

## 디버깅

### BPF 로그 확인
```bash
# 실시간 BPF printk 출력 확인
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep AID
```

거부된 접근은 다음과 같이 출력됩니다:
```
AID uid=50000 denied WRITE dev=... ino=...
```

### BPF 맵 내용 확인
```bash
# 맵이 pin되었는지 확인
ls -l /sys/fs/bpf/aid_inode_policies

# bpftool로 맵 내용 보기 (bpftool 설치 필요)
sudo bpftool map dump pinned /sys/fs/bpf/aid_inode_policies
```

### 로드된 BPF 프로그램 확인
```bash
sudo bpftool prog list | grep lsm
```

## 제약사항 및 알려진 이슈

1. **LSM BPF 커널 설정 필수**
   - 현재 커널: `CONFIG_BPF_LSM is not set` ❌
   - WSL2는 기본적으로 LSM BPF 미지원
   - 해결: 커널 재컴파일 또는 Native Linux 사용

2. **file_open 훅만 사용**
   - 이미 열린 파일 디스크립터를 통한 read/write는 검사 안 됨
   - fork 후 상속된 fd도 검사 안 됨

3. **Fail-open 정책**
   - 정책이 없는 파일은 모두 허용
   - 프로덕션에서는 fail-closed로 변경 권장

4. **Glob 패턴 제한**
   - `addagent` 실행 시점에 존재하는 파일만 등록
   - 이후 생성되는 파일은 정책 미적용

5. **실행 권한 미지원**
   - 현재는 read/write만 제어
   - execute 권한 검사 없음

## 에이전트 삭제

```bash
# 사용자 삭제
sudo userdel agent_myagent

# BPF 맵 엔트리는 수동 삭제 필요 (또는 재부팅 시 초기화)
```

## 문제 해결

### "bpf_object__load 실패: -1"
- LSM BPF가 비활성화되어 있음
- 커널 설정을 확인하고 필요시 재컴파일

### "Operation not permitted"
- root 권한으로 실행하세요
- `sudo` 사용

### "glob: '/path/to/*'에 매칭되는 파일이 없습니다"
- 파일을 먼저 생성하거나
- 해당 규칙을 manifest에서 제거

### "useradd 실패"
- 이미 사용자가 존재하는지 확인: `id agent_<name>`
- 기존 사용자 삭제: `sudo userdel agent_<name>`

## 라이선스

GPL-2.0
