#!/bin/bash
# AID 시스템 테스트 스크립트

set -e

echo "=== AID 테스트 스크립트 ==="
echo

# Root 권한 체크
if [ "$EUID" -ne 0 ]; then
    echo "❌ 이 스크립트는 root 권한으로 실행해야 합니다."
    echo "   sudo $0"
    exit 1
fi

# 1. 테스트 파일 생성
echo "[1/6] 테스트 파일 생성..."
echo "This file allows read only" > /tmp/allowed_read.txt
echo "This file allows read and write" > /tmp/allowed_write.txt
echo "This file is denied" > /tmp/denied.txt
chmod 666 /tmp/allowed_*.txt /tmp/denied.txt
echo "✅ 테스트 파일 생성 완료"
echo

# 2. eBPF LSM 로드
echo "[2/6] eBPF LSM 프로그램 로드..."
if ./src/aid_lsm_loader; then
    echo "✅ LSM 로드 성공"
else
    echo "❌ LSM 로드 실패 - 커널에서 CONFIG_BPF_LSM=y 설정 필요"
    echo "   현재 커널은 LSM BPF를 지원하지 않을 수 있습니다."
    exit 1
fi
echo

# 3. BPF 맵 확인
echo "[3/6] BPF 맵 확인..."
if [ -e /sys/fs/bpf/aid_inode_policies ]; then
    echo "✅ BPF 맵이 /sys/fs/bpf/aid_inode_policies에 pin됨"
else
    echo "❌ BPF 맵을 찾을 수 없습니다"
    exit 1
fi
echo

# 4. 에이전트 등록
echo "[4/6] 에이전트 등록..."
if ./src/addagent example_manifest.yaml; then
    echo "✅ 에이전트 등록 완료"
else
    echo "❌ 에이전트 등록 실패"
    exit 1
fi
echo

# 5. 에이전트 사용자 확인
echo "[5/6] 에이전트 사용자 확인..."
if id agent_testagent &>/dev/null; then
    AGENT_UID=$(id -u agent_testagent)
    echo "✅ agent_testagent 생성됨 (UID: $AGENT_UID)"
else
    echo "❌ agent_testagent 사용자를 찾을 수 없습니다"
    exit 1
fi
echo

# 6. 권한 테스트
echo "[6/6] 권한 테스트..."
echo

echo "테스트 1: 읽기 허용 파일 읽기 (성공해야 함)"
if sudo -u agent_testagent cat /tmp/allowed_read.txt &>/dev/null; then
    echo "  ✅ 읽기 성공"
else
    echo "  ❌ 읽기 실패 (성공해야 함)"
fi

echo "테스트 2: 읽기 허용 파일 쓰기 (실패해야 함)"
if sudo -u agent_testagent sh -c 'echo "test" > /tmp/allowed_read.txt' 2>/dev/null; then
    echo "  ❌ 쓰기 성공 (실패해야 함)"
else
    echo "  ✅ 쓰기 거부됨 (Permission denied)"
fi

echo "테스트 3: 읽기/쓰기 허용 파일 읽기 (성공해야 함)"
if sudo -u agent_testagent cat /tmp/allowed_write.txt &>/dev/null; then
    echo "  ✅ 읽기 성공"
else
    echo "  ❌ 읽기 실패 (성공해야 함)"
fi

echo "테스트 4: 읽기/쓰기 허용 파일 쓰기 (성공해야 함)"
if sudo -u agent_testagent sh -c 'echo "modified" > /tmp/allowed_write.txt' 2>/dev/null; then
    echo "  ✅ 쓰기 성공"
else
    echo "  ❌ 쓰기 실패 (성공해야 함)"
fi

echo "테스트 5: 거부된 파일 읽기 (실패해야 함)"
if sudo -u agent_testagent cat /tmp/denied.txt 2>/dev/null; then
    echo "  ❌ 읽기 성공 (실패해야 함)"
else
    echo "  ✅ 읽기 거부됨 (Permission denied)"
fi

echo
echo "=== 테스트 완료 ==="
echo
echo "정리 방법:"
echo "  sudo userdel agent_testagent"
echo "  rm /tmp/allowed_*.txt /tmp/denied.txt"
