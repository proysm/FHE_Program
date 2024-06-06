#include <bits/stdc++.h>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void send_encrypted_data(const vector<double>& rates, const SEALContext& context, const PublicKey& public_key, vector<Ciphertext>& encrypted_rates);
void handle_data(const vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key);
void test_key_validity(const SEALContext& context, const PublicKey& public_key, const SecretKey& secret_key);

vector<double> rates = { 0.1, 0.2, -0.05, 0.15, -0.1 }; // 예제 수익률 데이터

int main() {
    cout << "Start StockRank Program" << endl;

    EncryptionParameters params(scheme_type::ckks); // SEAL initialization: CKKS

    size_t poly_modulus_degree = 8192; // Polynomial modulus degree
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    auto context = SEALContext(params);
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
            encrypted_rate.scale() = scale; // 스케일을 명시적으로 설정
            encrypted_rates.push_back(encrypted_rate);

            // 디버깅 메시지
            cout << "Rate: " << rate << " encoded and encrypted." << endl;
        }
        cout << "Encrypted data sent to server." << endl;
    } catch (const exception& e) {
        cerr << "Exception in send_encrypted_data: " << e.what() << endl;
    }
}

void handle_data(const vector<Ciphertext>& encrypted_rates, const SEALContext& context, const SecretKey& secret_key, const PublicKey& public_key) {
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

        for (size_t i = 1; i < encrypted_rates.size(); ++i) {
            // 비교를 위한 차이 계산
            Ciphertext diff_max, diff_min;
            evaluator.sub(encrypted_rates[i], max_encrypted, diff_max);
            evaluator.sub(min_encrypted, encrypted_rates[i], diff_min);

            // Rescale to match scales
            evaluator.rescale_to_next_inplace(diff_max);
            evaluator.rescale_to_next_inplace(diff_min);

            // Match scales and levels
            diff_max.scale() = scale;
            diff_min.scale() = scale;
            parms_id_type last_parms_id = diff_max.parms_id();

            evaluator.mod_switch_to_inplace(max_encrypted, last_parms_id);
            evaluator.mod_switch_to_inplace(min_encrypted, last_parms_id);

            // Ensure max_encrypted and min_encrypted are on the same level and scale
            if (max_encrypted.parms_id() != diff_max.parms_id() || min_encrypted.parms_id() != diff_min.parms_id()) {
                throw runtime_error("Parameter mismatch after rescale and mod switch.");
            }

            // Create a ciphertext of zero for comparison
            Plaintext plain_zero;
            encoder.encode(0.0, scale, plain_zero);

            Ciphertext zero_encrypted;
            Encryptor encryptor(context, public_key);
            encryptor.encrypt(plain_zero, zero_encrypted);
            evaluator.mod_switch_to_inplace(zero_encrypted, last_parms_id);

            // Calculate is_greater
            Ciphertext is_greater;
            evaluator.add(diff_max, zero_encrypted, is_greater);
            evaluator.multiply_inplace(is_greater, encrypted_rates[i]);
            evaluator.relinearize_inplace(is_greater, relin_keys);
            evaluator.rescale_to_next_inplace(is_greater);
            is_greater.scale() = scale;

            // Update max_encrypted
            parms_id_type is_greater_parms_id = is_greater.parms_id();
            // evaluator.mod_switch_to_inplace(max_encrypted, is_greater_parms_id);
            evaluator.add_inplace(max_encrypted, is_greater);

            // Calculate is_lesser
            Ciphertext is_lesser;
            evaluator.add(diff_min, zero_encrypted, is_lesser);
            evaluator.multiply_inplace(is_lesser, encrypted_rates[i]);
            evaluator.relinearize_inplace(is_lesser, relin_keys);
            evaluator.rescale_to_next_inplace(is_lesser);
            is_lesser.scale() = scale;

            // Update min_encrypted
            parms_id_type is_lesser_parms_id = is_lesser.parms_id();
            evaluator.mod_switch_to_inplace(min_encrypted, is_lesser_parms_id);
            evaluator.add_inplace(min_encrypted, is_lesser);
        }

        // Decrypt and decode the results
        Plaintext plain_max_result, plain_min_result;
        decryptor.decrypt(max_encrypted, plain_max_result);
        decryptor.decrypt(min_encrypted, plain_min_result);

        vector<double> max_result, min_result;
        encoder.decode(plain_max_result, max_result);
        encoder.decode(plain_min_result, min_result);

        cout << "Maximum return rate: " << max_result[0] << endl;
        cout << "Minimum return rate: " << min_result[0] << endl;

        // Decrypt and rank all participant rates
        vector<pair<double, size_t>> rates;
        for (size_t i = 0; i < encrypted_rates.size(); ++i) {
            Plaintext plain_rate;
            decryptor.decrypt(encrypted_rates[i], plain_rate);
            vector<double> rate;
            encoder.decode(plain_rate, rate);
            rates.push_back({rate[0], i + 1});
        }

        // Sort and display rankings
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
    double scale = pow(2.0, 40); // 적절한 스케일 선택

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
