#include <bits/stdc++.h>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void send_encrypted_data(const vector<double>& rates, const SEALContext& context, const PublicKey& public_key, vector<Ciphertext>& encrypted_rates);
void handle_data(vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key);
void decrypted_data();
void test_key_validity(const SEALContext& context, const PublicKey& public_key, const SecretKey& secret_key);

vector<double> rates = { 23.1, -25.0, 12.5, -10.5, 50.0 }; // 예제 수익률 데이터

int main() {
    cout << "Start StockRank Program" << endl;

    EncryptionParameters params(scheme_type::ckks); // SEAL initialization: CKKS

    size_t poly_modulus_degree = 16384; // Polynomial modulus degree
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 60}));

    SEALContext context(params);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    test_key_validity(context, public_key, secret_key); // 키 유효성 테스트 함수 호출

    vector<Ciphertext> encrypted_rates;
    send_encrypted_data(rates, context, public_key, encrypted_rates); // 데이터 보내기

    handle_data(encrypted_rates, context, secret_key, public_key);

    cout << "End of StockRank Program" << endl;
    return 0;
}

void send_encrypted_data(const vector<double>& rates, const SEALContext& context, const PublicKey& public_key, vector<Ciphertext>& encrypted_rates) {
    try {
        Encryptor encryptor(context, public_key);
        CKKSEncoder encoder(context);

        double scale = pow(2.0, 40);

        for (double rate : rates) {
            Plaintext plain_rate;
            encoder.encode(rate, scale, plain_rate);
            Ciphertext encrypted_rate;
            encryptor.encrypt(plain_rate, encrypted_rate);
            encrypted_rate.scale() = scale; // 스케일
            encrypted_rates.push_back(encrypted_rate);

            // 디버깅 메시지
            cout << "Rate: " << rate << " encoded and encrypted." << endl;
        }
        cout << "Encrypted data prepared." << endl;
    } catch (const exception& e) {
        cerr << "Exception in send_encrypted_data: " << e.what() << endl;
    }
}

void handle_data(vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key) {
    try {
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder encoder(context);
        RelinKeys relin_keys;
        KeyGenerator keygen(context);
        keygen.create_relin_keys(relin_keys);

        double scale = pow(2.0, 40);

        // 최대값과 최소값 초기화
        Ciphertext max_encrypted = encrypted_rates[0];
        Ciphertext min_encrypted = encrypted_rates[0];
        
        for (size_t i = 1; i < encrypted_rates.size(); ++i) {
            Ciphertext diff_max, diff_min, sign_diff_max, sign_diff_min;
            Plaintext plain_half;
            encoder.encode(0.5, scale, plain_half);

            // 현재 암호문과 최대/최소 암호문의 차이 계산
            evaluator.sub(encrypted_rates[i], max_encrypted, diff_max);
            evaluator.sub(min_encrypted, encrypted_rates[i], diff_min);

            // 차이에 0.5 더하기 (부호 판단용)
            evaluator.add_plain(diff_max, plain_half, sign_diff_max);
            evaluator.add_plain(diff_min, plain_half, sign_diff_min);

            // 부호 판단을 위해 복호화 (실제 환경에서는 불가능할 수 있음, 시뮬레이션용)
            Plaintext decoded_max, decoded_min;
            decryptor.decrypt(sign_diff_max, decoded_max);
            decryptor.decrypt(sign_diff_min, decoded_min);

            vector<double> decoded_values_max, decoded_values_min;
            encoder.decode(decoded_max, decoded_values_max);
            encoder.decode(decoded_min, decoded_values_min);

            // 최대값과 최소값 업데이트
            if (decoded_values_max[0] > 0.5) {
                max_encrypted = encrypted_rates[i];
            }
            if (decoded_values_min[0] > 0.5) {
                min_encrypted = encrypted_rates[i];
            }
        }

        // 최대값과 최소값 복호화 및 출력
        Plaintext plain_max, plain_min;
        decryptor.decrypt(max_encrypted, plain_max);
        decryptor.decrypt(min_encrypted, plain_min);

        vector<double> max_value, min_value;
        encoder.decode(plain_max, max_value);
        encoder.decode(plain_min, min_value);

        cout << "Maximum value: " << max_value[0] << endl;
        cout << "Minimum value: " << min_value[0] << endl;

        // 각 암호문의 복호화된 값을 저장할 벡터
        vector<double> decrypted_values(encrypted_rates.size());

        // 모든 암호문을 복호화하여 값을 저장
        for (size_t i = 0; i < encrypted_rates.size(); ++i) {
            Plaintext plain;
            decryptor.decrypt(encrypted_rates[i], plain);
            vector<double> rate;
            encoder.decode(plain, rate);
            decrypted_values[i] = rate[0];
        }

        // 복호화된 값과 인덱스를 쌍으로 저장하여 정렬
        vector<pair<double, size_t>> sorted_values;
        for (size_t i = 0; i < decrypted_values.size(); ++i) {
            sorted_values.emplace_back(decrypted_values[i], i + 1);
        }

        // 정렬
        sort(sorted_values.begin(), sorted_values.end(), greater<pair<double, size_t>>());

        // 등수 출력
        cout << "Rankings:" << endl;
        for (size_t i = 0; i < sorted_values.size(); ++i) {
            cout << "Rank " << i + 1 << ": Participant " << sorted_values[i].second << " with return rate " << sorted_values[i].first << endl;
        }

    } catch (const exception& e) {
        cerr << "Exception in handle_data: " << e.what() << endl;
    }
}




void test_key_validity(const SEALContext& context, const PublicKey& public_key, const SecretKey& secret_key) {
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    double original_value = 123.456; // 테스트할 값
    double scale = pow(2.0, 40); 

    Plaintext plaintext;
    encoder.encode(original_value, scale, plaintext);

    Ciphertext ciphertext;
    encryptor.encrypt(plaintext, ciphertext);

    Plaintext decrypted_plaintext;
    decryptor.decrypt(ciphertext, decrypted_plaintext);

    vector<double> decoded_values;
    encoder.decode(decrypted_plaintext, decoded_values);

    if (abs(decoded_values[0] - original_value) < 0.001) {
        cout << "Key test passed: " << decoded_values[0] << " matches " << original_value << endl;
    } else {
        cout << "Key test failed: Decoded value " << decoded_values[0] << " does not match original " << original_value << endl;
    }
}
