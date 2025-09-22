# PQC KAT

* **ML-DSA 44, 65, 87**
* **ML-KEM 512, 768, 1024**
* **SMAUG-T 1, 3, 5**

**BOLD** is complete

# Source

ML-DSA, ML-KEM test vector url: "https://github.com/post-quantum-cryptography/KAT"

SMAUG-T test vector url: "https://github.com/hmchoe0528/SMAUG-T_public/tree/main/KAT"

Make SMAUG-T test vector url: "https://github.com/SJChoiiii/for_SMAUG-T-KAT"


${\textsf{\color{green}SMAUG-T test vector의 경우, AES-DRBG의 입력에 대한 seed 만이 존재하며, rounding 기준값에 대한 오류 수정을 반영한 KAT 문서가 존재하지 않음}}$
${\textsf{\color{green}따라서 각 KAT에서의 실제 keypair seed, implicit seed, mu seed, 올바른 ctxt를 뽑아, 새로운 KAT 문서를 작성하여 진행}}$
${\textsf{\color{green}이 때, 오류 사항은 ct에만 발생하기 때문에, 나머지 모든 값은 기존의 KAT 문서와 동일함}}$


