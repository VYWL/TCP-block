## TCP-block

Out-bound 방식으로 Capture한 TCP 패킷을 분석하여 유해사이트 차단 및 리다이렉트 구현하기 😉

### 구현 단계

-   [ ] TCP 패킷 잡기
-   [ ] 잡은 패킷이 IP, TCP 패킷인지 검증
-   [ ] `genBlocking` 함수 설계
-   [ ] Forward & Backward 케이스 나눠서 값 설정
-   [ ] 만든 패킷을 send하는 과정
-   [ ] 테스트 케이스 10회, 발견된 버그 수정 및 과제 제출

### 사용 방법

```sh
$ git clone https://github.com/VYWL/TCP-block
$ cd TCP-block
$ make
$ sudo ./tcp-block <interface> <pattern>
```

### 기타사항

-   문제 있을시 연락.
