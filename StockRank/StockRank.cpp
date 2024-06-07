#include <bits/stdc++.h>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void send_encrypted_data(const vector<double>& rates, const SEALContext& context, const PublicKey& public_key, vector<Ciphertext>& encrypted_rates);
void handle_data(vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key);
void test_key_validity(const SEALContext& context, const PublicKey& public_key, const SecretKey& secret_key);

vector<double> rates = { 0.1, 0.2, 0.3, 0.4, 0.5 }; // 예제 수익률 데이터

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

    // 키 유효성 테스트 함수 호출
    test_key_validity(context, public_key, secret_key);

    vector<Ciphertext> encrypted_rates;
    send_encrypted_data(rates, context, public_key, encrypted_rates);

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

        // 최대값과 최소값 찾기
        Ciphertext max_encrypted = encrypted_rates[0];
        Ciphertext min_encrypted = encrypted_rates[0];
        
        int base_level = context.get_context_data(encrypted_rates[0].parms_id())->chain_index(); // 기준 레벨 설정


        // encrypted_rates.size()
        for (size_t i = 1; i < encrypted_rates.size(); ++i) {

            // 반복 시작 시 모든 암호문을 기준 레벨에 맞추고 스케일 조정
            for (auto& rate : encrypted_rates) {
                while (context.get_context_data(rate.parms_id())->chain_index() > base_level) {
                    evaluator.rescale_to_next_inplace(rate);
                    rate.scale() = scale;
                }
            }

            // 비교를 위한 차이 계산
            Ciphertext diff_max, diff_min;
            evaluator.sub(encrypted_rates[i], max_encrypted, diff_max);
            evaluator.sub(min_encrypted, encrypted_rates[i], diff_min);

            // 스케일 및 레벨 출력
            cout << "Scale (diff_max): " << diff_max.scale() << endl;
            cout << "Scale (diff_min): " << diff_min.scale() << endl;
            cout << "Level (diff_max): " << context.get_context_data(diff_max.parms_id())->chain_index() << endl;
            cout << "Level (diff_min): " << context.get_context_data(diff_min.parms_id())->chain_index() << endl;

            // 연산 전 레벨 맞추기
            parms_id_type last_parms_id = diff_max.parms_id();
            evaluator.mod_switch_to_inplace(max_encrypted, last_parms_id);
            evaluator.mod_switch_to_inplace(min_encrypted, last_parms_id);

            cout << "Scale (max_encrypted): " << max_encrypted.scale() << endl;
            cout << "Level (max_encrypted): " << context.get_context_data(max_encrypted.parms_id())->chain_index() << endl;

            if (max_encrypted.parms_id() != diff_max.parms_id() || min_encrypted.parms_id() != diff_min.parms_id()) {
                throw runtime_error("Parameter mismatch after rescale and mod switch.");
            }

            // 0 및 0.5 암호문 생성
            Plaintext plain_zero;
            encoder.encode(0.0, scale, plain_zero);
            Ciphertext zero_encrypted;
            Encryptor encryptor(context, public_key);
            encryptor.encrypt(plain_zero, zero_encrypted);
            evaluator.mod_switch_to_inplace(zero_encrypted, last_parms_id);

            Plaintext plain_half;
            encoder.encode(0.5, scale, plain_half);
            evaluator.mod_switch_to_inplace(plain_half, diff_max.parms_id());

            // sign_diff_max 계산
            Ciphertext sign_diff_max;
            evaluator.add_plain(diff_max, plain_half, sign_diff_max);
            sign_diff_max.scale() = scale;

            cout << "Scale after addition (sign_diff_max): " << sign_diff_max.scale() << endl;
            cout << "Level after addition (sign_diff_max): " << context.get_context_data(sign_diff_max.parms_id())->chain_index() << endl;

            // sign_diff_max와 encrypted_rates[i]의 레벨 맞추기
            evaluator.mod_switch_to_inplace(sign_diff_max, encrypted_rates[i].parms_id());
            evaluator.mod_switch_to_inplace(encrypted_rates[i], sign_diff_max.parms_id());

            // 곱셈 후 레벨과 스케일을 맞춤
            evaluator.multiply_inplace(sign_diff_max, encrypted_rates[i]);
            evaluator.relinearize_inplace(sign_diff_max, relin_keys);
            evaluator.rescale_to_next_inplace(sign_diff_max);
            sign_diff_max.scale() = scale;

            cout << "Scale after multiplication (sign_diff_max): " << sign_diff_max.scale() << endl;
            cout << "Level after multiplication (sign_diff_max): " << context.get_context_data(sign_diff_max.parms_id())->chain_index() << endl;

            // max_encrypted의 레벨과 스케일을 sign_diff_max에 맞춤
            evaluator.mod_switch_to_inplace(max_encrypted, sign_diff_max.parms_id());
            if (max_encrypted.scale() != sign_diff_max.scale()) {
                max_encrypted.scale() = sign_diff_max.scale();
            }
            evaluator.add_inplace(max_encrypted, sign_diff_max);

            // sign_diff_min 계산
            evaluator.mod_switch_to_inplace(plain_half, diff_min.parms_id());
            Ciphertext sign_diff_min;
            evaluator.add_plain(diff_min, plain_half, sign_diff_min);
            sign_diff_min.scale() = scale;

            evaluator.mod_switch_to_inplace(sign_diff_min, encrypted_rates[i].parms_id());
            evaluator.mod_switch_to_inplace(encrypted_rates[i], sign_diff_min.parms_id());

            evaluator.multiply_inplace(sign_diff_min, encrypted_rates[i]);
            evaluator.relinearize_inplace(sign_diff_min, relin_keys);
            evaluator.rescale_to_next_inplace(sign_diff_min);
            sign_diff_min.scale() = scale;

            cout << "Scale after multiplication (sign_diff_min): " << sign_diff_min.scale() << endl;
            cout << "Level after multiplication (sign_diff_min): " << context.get_context_data(sign_diff_min.parms_id())->chain_index() << endl;

            // min_encrypted의 레벨과 스케일을 sign_diff_min에 맞춤
            evaluator.mod_switch_to_inplace(min_encrypted, sign_diff_min.parms_id());
            if (min_encrypted.scale() != sign_diff_min.scale()) {
                min_encrypted.scale() = sign_diff_min.scale();
            }
            evaluator.add_inplace(min_encrypted, sign_diff_min);

            base_level--;
        }

        // 해독 시작
        Plaintext plain_max_result, plain_min_result;
        decryptor.decrypt(max_encrypted, plain_max_result);
        decryptor.decrypt(min_encrypted, plain_min_result);

        vector<double> max_result, min_result;
        encoder.decode(plain_max_result, max_result);
        encoder.decode(plain_min_result, min_result);

        cout << "Maximum return rate: " << max_result[0] << endl;
        cout << "Minimum return rate: " << min_result[0] << endl;

        vector<pair<double, size_t>> rates;
        for (size_t i = 0; i < encrypted_rates.size(); ++i) {
            Plaintext plain_rate;
            decryptor.decrypt(encrypted_rates[i], plain_rate);
            vector<double> rate;
            encoder.decode(plain_rate, rate);
            rates.push_back({rate[0], i + 1});
        }

        // 등수 정렬
        sort(rates.begin(), rates.end(), greater<pair<double, size_t>>());

        cout << "Rankings:" << endl;
        for (size_t i = 0; i < rates.size(); ++i) {
            cout << "Rank " << i + 1 << ": Participant " << rates[i].second << " with return rate " << rates[i].first << endl;
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
