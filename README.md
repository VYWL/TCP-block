## TCP-block

Out-bound 방식으로 Capture한 TCP 패킷을 분석하여 유해사이트 차단 및 리다이렉트 구현하기 😉

### 구현 단계

-   [x] Sender 측에서 송신하는 TCP 패킷 Capture (이전 arp-spoof 연장선)
-   [x] HTTP Payload 중, 유해사이트가 Host인 패킷 고르기 (이전 netfilter 연장선)
- ~~[ ] Port 값을 통해서 HTTPS 여부 확인~~
-   [x] EthHdr, IpHdr, TcpHdr 구조체 정의
-   [x] 어느 방향으로 보내는지에 따른, SMAC, DMAC 설정
-   [x] IP헤더 기본 값 설정 및 방향에 따른 flag 비트 수정, sip & dip설정 등
-   [x] IP헤더 checksum 설정을 위한 값 계산
-   [x] TCP헤더 기본 값 설정 및 방향에 따른 flag 비트 수정, sip & dip설정 등
-   [x] TCP헤더 checksum 설정을 위한 값 계산 (이전 ip헤더에서 계산한 checksum 활용)
-   [x] 양 방향 패킷 송신 테스트
-   [x] 차단 여부 관련 테스트
-   [x] TCP 패킷 잡기
-   [x] 잡은 패킷이 IP, TCP 패킷인지 검증
-   [x] `genBlocking` 함수 설계
-   [x] Forward & Backward 케이스 나눠서 값 설정
-   [x] 만든 패킷을 send하는 과정
-   [x] 테스트 케이스 10회, 발견된 버그 수정 및 과제 제출

### 사용 방법

```sh
$ git clone https://github.com/VYWL/TCP-block
$ cd TCP-block
$ make
$ sudo ./tcp-block <interface> <pattern>
```

### 기타사항

-   문제 있을시 연락.
