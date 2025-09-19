# PQC KAT
* **ML-DSA 44, 65, 87**
* **ML-KEM 512, 768, 1024**
* **SMAUG-T 1, 3, 5**


**BOLD** is complete

ML-DSA, ML-KEM test vector url: "https://github.com/post-quantum-cryptography/KAT"

SMAUG-T test vector url: "https://github.com/hmchoe0528/SMAUG-T_public/tree/main/KAT"

* SMAUG-T test vector의 경우, AES-DRBG의 입력에 대한 seed 만이 존재하기 때문에, 각 KAT에서의 실제 keypair seed, implicit seed, mu seed를 뽑아서 새로운 KAT 문서를 작성하여 진행함

pk, sk, ct, ss의 모든 test vector가 맞음을 확인