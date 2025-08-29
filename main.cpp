// general imports
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>

#include <memory>  // for unique_ptr
#include <fstream> // to read and write file
// to encode
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sstream> // to split string
#include <iomanip> // to print hex keys

using namespace std;

// source: https://www.youtube.com/watch?v=MNeX4EGtR5Y
// source: https://cplusplus.com/doc/tutorial/files/

class Decoder
{
    unique_ptr<ifstream> open_file(string source_file)
    {
        // open file to decrypt
        auto file_to_decrypt = make_unique<ifstream>();
        file_to_decrypt->open(source_file, ios::binary);
        return file_to_decrypt;
    };

    // source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
        abort();
    };
    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext)
    {
        EVP_CIPHER_CTX *ctx;

        int len;

        int plaintext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
         * Initialise the decryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits
         */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
         * Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary.
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();
        plaintext_len = len;

        /*
         * Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
            handleErrors();
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }

    void decrypt_file_with_aes(unique_ptr<ifstream> &file_ptr, string password, string iv) {
        

    };

    bool save_decrypted_file(string target_file)
    {
        // save decrypted file
        ofstream myfile; // declare object
        myfile.open(target_file);
        myfile << "Writing this to a file.\n";
        myfile.close();
        return true;
    };

    list<string> extract_file_and_extension(string filename){
        string target_filename;
        string target_file_extension;

        size_t pos = filename.rfind('.');
        if (pos != string::npos)
        {
            target_filename = filename.substr(0, pos);
            target_file_extension = filename.substr(pos + 1);
        }
        else
        {
            target_filename = filename;
            target_file_extension = ""; // no extension found
        }
        return {target_filename, target_file_extension};
    }
    
public:
    bool decode_file(string target_file, string target_file_format, string aes_password, string iv)
    {
        list<string> filename_and_extension = extract_file_and_extension(target_file);
        string filename = filename_and_extension[0];
        string file_extension = filename_and_extension[1];

        auto file_ptr = open_file(target_file + '.' + target_file_format);
        string decrypted_file = decrypt_file_with_aes(file_ptr, aes_password, iv);
        bool success = save_decrypted_file(decrypted_file);
        return success;
    }
};

class Encoder
{
    unique_ptr<ifstream> open_file(string source_file)
    {
        // open file to encrypt
        auto file_to_encrypt = make_unique<ifstream>();
        file_to_encrypt->open(source_file, ios::binary);
        return file_to_encrypt;
    };

    // source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
        abort();
    };

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext)
    {
        EVP_CIPHER_CTX *ctx;

        int len;

        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
         * Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits
         */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
         * Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();
        ciphertext_len = len;

        /*
         * Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            handleErrors();
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    };

    bool generate_aes_key(unsigned char *key, unsigned char *iv)
    {
        int aes_size_bytes = 32;
        int iv_size_bytes = 16;

        if (!RAND_bytes(key, aes_size_bytes)) // generate random 32 bytes and store them in key
        {
            return false; // handle error
        };
        if (!RAND_bytes(iv, iv_size_bytes)) // this is not secret but must be unique
        {
            return false; // handle error
        };

        // source: https://medium.com/@ryan_forrester_/c-cout-in-hex-practical-guide-224db1748a3d
        cout << "AES Key: ";
        for (int i = 0; i < aes_size_bytes; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
        };
        cout << dec << endl; // return to decimal

        cout << "AES IV:  ";
        for (int i = 0; i < iv_size_bytes; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(iv[i]);
        }
        cout << dec << endl;
        return true;
    };

    vector<unsigned char> encode_file_with_aes(ifstream &file_to_encrypt)
    {
        // read file to encrypt as string with dynamic buffer
        std::vector<unsigned char> file_as_text((std::istreambuf_iterator<char>(file_to_encrypt)),
                                                std::istreambuf_iterator<char>());
        file_to_encrypt.close();

        // encode file
        unsigned char key[32];     // 32 bytes, 256 bits for AES-256
        unsigned char iv[16];      // 16 bytes of initialization for 'CBC mode', adds randomization so twin messages are not encrypted equally
        generate_aes_key(key, iv); // same as Fernet in Python

        vector<unsigned char> ciphertext(file_as_text.size() + EVP_MAX_BLOCK_LENGTH); // dynamic buffer for ciphertext (large enough for original text + AES padding)

        // EVP_MAX_BLOCK_LENGTH states largest available padding

        int ciphertext_len = encrypt(
            file_as_text.data(), // bytes of data string
            file_as_text.size(), // string size in bytes
            key,                 // AES key
            iv,                  // initialization vector
            ciphertext.data());  // output buffer

        ciphertext.resize(ciphertext_len); // downsize to required memory

        return ciphertext;
    }

    bool save_encrypted_file(const string &filename, const vector<unsigned char> &encrypted_file)
    {
        // save encrypted file
        ofstream out(filename, std::ios::binary);
        out.write(reinterpret_cast<const char *>(encrypted_file.data()), encrypted_file.size()); // it reads bytes as char*
        return true;
    };
    
    list<string> extract_file_and_extension(string filename){
        string target_filename;
        string target_file_extension;

        size_t pos = filename.rfind('.');
        if (pos != string::npos)
        {
            target_filename = filename.substr(0, pos);
            target_file_extension = filename.substr(pos + 1);
        }
        else
        {
            target_filename = filename;
            target_file_extension = ""; // no extension found
        }
        return {target_filename, target_file_extension};
    }

public:
    bool encode_file(string target_file = "")
    {
        // split target_file name and extension
        list<string> filename_and_extension = extract_file_and_extension(target_file);
        string filename = filename_and_extension[0];
        string file_extension = filename_and_extension[1];

        size_t pos = target_file.rfind('.');
        if (pos != string::npos)
        {
            target_filename = target_file.substr(0, pos);
            target_file_extension = target_file.substr(pos + 1);
        }
        else
        {
            target_filename = target_file;
            target_file_extension = ""; // no extension found
        }

        auto file_ptr = open_file(target_file + '.' + target_file_extension);
        std::vector<unsigned char> encrypted_file = encode_file_with_aes(*file_ptr);
        bool success = save_encrypted_file(target_filename + "_encrypted." + target_file_extension, encrypted_file);
        return success;
    };
};

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        cout << "Use: main.exe <1 to encrypt, 0 to decrypt > <file> <password (optional)>\n";
        return 1;
    }

    Encoder encoder;
    string operation = argv[1];
    string target_file = argv[2];
    string password = argv[3]; // not used in encoding
    string iv = argv[4]; // initialization vector for AES

    if (operation != "1" && operation != "0")
    {
        cout << "Invalid option. Use 1 to encrypt or 0 to decrypt.\n";
        return 1;
    }

    if (operation == "1")
    {
        encoder.encode_file(target_file);
    }
    else
    {
        cout << "Decoding not implemented yet.\n";
        encoder.decode_file(target_file, password, iv);
    }

    return 0;
};
