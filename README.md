# FHE Program 🔐
이 프로젝트는 Microsoft SEAL 라이브러리를 활용한 프로그램입니다. 주식 투자를 배경으로 하여 다양한 아이디어를 제시하고 선정된 하나의 아이디어를 구현하고자 합니다. 

<br>

## 목차
[소개](#소개)

[아이디어](#-아이디어-브레인스토밍)

[1. 첫 번째 아이디어](#1-첫-번째-아이디어) 

[2. 두 번째 아이디어](#2-두-번째-아이디어) 

[3. 세 번째 아이디어](#3-세-번째-아이디어) 

[구현](#-세-번째-아이디어-구현)

<br>

## 💡 아이디어 (브레인스토밍) 

> 주식투자를 배경으로한 동형암호 프로그램 제작 💰 💰 💰 



### 1. 첫 번째 아이디어
```
사용자의 투자 성향 분석
```
1. 사용자의 포트폴리오를 기반으로 사용자의 투자 종목의 개수, 종목당 투자액(주*주가), 종목당 시가총액을 고려하여 x% 이내의 표준편차를 가지면 10점, 밖의 표준편차를 가지면 5점을 부여한다.
2. 시가총액을 이용하여 우량주의 비중을 확인하고 70% 이상은 10점, 40% 이상은 5점, 나머지는 1점을 부여한다.
3. 따라서 사용자의 총 점수를 계산하여 사용자의 투자 성향을 분석한다. : *안전추구형 / 공격형*

<br>

**⚠️ 그러나 Microsoft SEAL은 덧셈 / 곱셈 / 뺄셈 만을 제공하므로 나누기, 표준편차 연산 등이 불가능해 보인다.**

<br>

### 2. 두 번째 아이디어
```
모의 투자 대회 1등 찾기
```
1. 모의 투자에 대회에 참가한 N명의 참가자들이 자신들의 초기자본과, 최종자본을 입력한다. 
2. 수익률이 가장 높은 사용자의 수익률을 공개한다.
3. 따라서 참가자들은 자신이 1등인지 아닌지 판단할 수 있다.

<br>

**⚠️ 그러나 Microsoft SEAL은 나누기 연산을 제공하지 않는다. 하지만 편법?!** 

🤖 GPT say...

Microsoft SEAL은 직접적인 나누기 연산을 제공하지 않습니다. SEAL 라이브러리는 주로 덧셈과 곱셈 연산을 지원하며, 나누기 연산을 구현하려면 간접적인 방법을 사용해야 합니다. CKKS 스킴을 사용하여 근사 연산을 통해 나누기를 구현할 수 있지만, 이는 직접적인 지원이 아니며, 정확한 나누기 연산이 아닙니다.

나누기 연산을 근사하는 방법
나누기 연산을 구현하는 일반적인 방법은 나누는 수의 역수를 구한 다음, 이를 곱하는 방식입니다. 예를 들어, 
𝑎
/
𝑏
를 계산하려면 
𝑎
×
(
1
/
𝑏
)
를 계산합니다. 동형암호 환경에서 역수를 구하는 것은 복잡하지만, 몇 가지 근사 방법을 사용할 수 있습니다.

CKKS 스킴을 사용한 근사 나누기
CKKS 스킴은 실수와 복소수 연산을 지원하며, 부동 소수점 연산을 근사할 수 있습니다. CKKS 스킴을 사용하면 실수 연산의 근사값을 계산할 수 있습니다. 여기서는 CKKS 스킴을 사용하여 나누기 연산을 근사하는 방법을 설명합니다.

<br>

### 3. 세 번째 아이디어
```
(두번째 아이디어를 아주 간단히 한) 모의 투자 대회 1등, 꼴등 찾기
```
1. 모의 투자에 대회에 참가한 N명의 참가자들이 자신들의 수익률을 직접 입력한다. **(차이점)**
2. 가장 높은 수익률과 가장 낮은 수익률을 공개한다. + (추가) 모든 등수를 공개한다.
3. 따라서 참가자들은 자신이 1등인지, 꼴등인지 혹은 어느 것도 아닌지 판단할 수 있다. 


🤖 최대 최소는 어떻게 ...

Microsoft SEAL은 빼기 연산을 지원하므로 비교 연산을 근사한다.

<br>

## 👾 세 번째 아이디어 구현 

### 0. 키 유효성 테스트 함수
```C++
void test_key_validity(const SEALContext& context, const PublicKey& public_key, const SecretKey& secret_key);
```
-> 실행 결과
```text
Key test passed: 123.456 matches 123.456
```


### 1. 주식 수익률 암호화 (Encrypt)

```C++
void send_encrypted_data(const vector<double>& rates, const SEALContext& context, const PublicKey& public_key, vector<Ciphertext>& encrypted_rates);
```
-> 실행 결과
```text
Rate: 23.1 encoded and encrypted.
Rate: -25 encoded and encrypted.
Rate: 12.5 encoded and encrypted.
Rate: -10.5 encoded and encrypted.
Rate: 50 encoded and encrypted.
Encrypted data prepared.
```

### 2. 암호화된 상태로 주식 데이터 계산 및 복호화 (handle_data)
```C++
void handle_data(vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key);
```
-> 실행 결과
```text
Maximum value: 50
Minimum value: -25
Rankings:
Rank 1: Participant 5 with return rate 50
Rank 2: Participant 1 with return rate 23.1
Rank 3: Participant 3 with return rate 12.5
Rank 4: Participant 4 with return rate -10.5
Rank 5: Participant 2 with return rate -25
```