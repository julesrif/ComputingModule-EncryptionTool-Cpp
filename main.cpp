// general imports
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>
#include <list>    // to use list of string
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
        if (!file_to_decrypt->is_open())
        {
            cerr << "Error: file cannot be opened " << source_file << endl;
            return nullptr;
        }
        return file_to_decrypt;
    };

    // source: https://www.geeksforgeeks.org/cpp/how-to-convert-hex-string-to-byte-array-in-cpp/
    vector<uint8_t> hexStringToByteArray(const string &hexString)
    {
        vector<uint8_t> byteArray;
        string cleanHex;

        // remove spaces and newlines
        for (char c : hexString)
        {
            if (!isspace(c))
                cleanHex += c;
        }

        if (cleanHex.length() % 2 != 0)
        {
            cerr << "Error: hex string length must be even\n";
            return {};
        }

        // Loop through the hex string, two characters at a time
        for (size_t i = 0; i < cleanHex.length(); i += 2)
        {
            // Extract two characters representing a byte
            string byteString = cleanHex.substr(i, 2);

            // Convert the byte string to a uint8_t value
            uint8_t byteValue = static_cast<uint8_t>(
                stoi(byteString, nullptr, 16));

            // Add the byte to the byte array
            byteArray.push_back(byteValue);
        }

        return byteArray;
    }

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

    vector<unsigned char> decrypt_file_with_aes(ifstream &file_to_decrypt, unsigned char *key)
    {
        ifstream &in = file_to_decrypt;
        in.seekg(0, ios::beg); // force cursor to beginning of file

        unsigned char init_vector[16];
        in.read(reinterpret_cast<char *>(init_vector), 16);                                             // read initialization vector from the encoded file, first 16 bytes
        vector<unsigned char> ciphertext((istreambuf_iterator<char>(in)), istreambuf_iterator<char>()); // read the rest of the encoded file
        in.close();                                                                                     // release memory

        vector<unsigned char> plaintext(ciphertext.size());

        int decrypted_len = decrypt(
            ciphertext.data(), // read pointer to data
            ciphertext.size(), // read size of the data to be read
            key,               // AES key to decode
            init_vector,       // initialization vector to decode
            plaintext.data()); // target variable

        plaintext.resize(decrypted_len); // adjust length of the output

        return plaintext;
    };

    bool save_decrypted_file(const string &target_file, vector<unsigned char> &decrypted_data)
    {
        // save decrypted file
        ofstream output_file(target_file, ios::binary); // open the target file where decode content goes to
        if (!output_file.is_open())
        {
            return false;
        } // handle error
        output_file.write(reinterpret_cast<const char *>(decrypted_data.data()), decrypted_data.size()); // write decoded content
        output_file.close();                                                                             // close the file to release memory
        return true;
    };

    list<string> extract_file_and_extension(string filename)
    {
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
    bool decode_file(string target_file, string aes_password)
    {
        // split full name into parts
        list<string> filename_and_extension = extract_file_and_extension(target_file);
        string filename = filename_and_extension.front();
        string file_extension = filename_and_extension.back();

        vector<unsigned char> key = hexStringToByteArray(aes_password); // decode password

        auto file_ptr = open_file(filename + '.' + file_extension);                                  // create pointer to encoded file that will be decoded
        vector<unsigned char> decrypted_data = decrypt_file_with_aes(*file_ptr, key.data());         // decode content
        bool success = save_decrypted_file(filename + "_decoded." + file_extension, decrypted_data); // save to file
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
        if (!file_to_encrypt->is_open())
        {
            cerr << "Error: file cannot be opened " << source_file << endl;
            return nullptr;
        }
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

    bool generate_aes_key(unsigned char *key, unsigned char *init_vector)
    {
        int aes_size_bytes = 32;
        int iv_size_bytes = 16;

        if (!RAND_bytes(key, aes_size_bytes)) // generate random 32 bytes and store them in key
        {
            return false; // handle error
        };
        if (!RAND_bytes(init_vector, iv_size_bytes)) // this is not secret but must be unique
        {
            return false; // handle error
        };

        // source: https://medium.com/@ryan_forrester_/c-cout-in-hex-practical-guide-224db1748a3d
        cout << "Key: ";
        for (int i = 0; i < aes_size_bytes; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
        };
        cout << dec << endl; // return to decimal
        cout << "(Copy this key, you will not be able to generate it again.)" << endl;
        cout << dec << endl;
        return true;
    };

    vector<unsigned char> encode_file_with_aes(ifstream &file_to_encrypt, unsigned char *key, unsigned char *init_vector)
    {
        // read file to encrypt as string with dynamic buffer
        std::vector<unsigned char> file_as_text((std::istreambuf_iterator<char>(file_to_encrypt)),
                                                std::istreambuf_iterator<char>());
        file_to_encrypt.close();

        vector<unsigned char> ciphertext(file_as_text.size() + EVP_MAX_BLOCK_LENGTH); // dynamic buffer for ciphertext (large enough for original text + AES padding)

        // EVP_MAX_BLOCK_LENGTH states largest available padding

        int ciphertext_len = encrypt(
            file_as_text.data(), // bytes of data string
            file_as_text.size(), // string size in bytes
            key,                 // AES key
            init_vector,         // initialization vector
            ciphertext.data());  // output buffer

        ciphertext.resize(ciphertext_len); // downsize to required memory

        return ciphertext;
    }

    bool save_encrypted_file(const string &filename, const vector<unsigned char> &encrypted_file, const unsigned char *init_vector)
    {
        ofstream out(filename, std::ios::binary);                   // save encrypted file
        out.write(reinterpret_cast<const char *>(init_vector), 16); // write to output_file iv
        // write the rest of the file
        out.write(reinterpret_cast<const char *>(encrypted_file.data()), encrypted_file.size()); // it reads bytes as char*
        return true;
    };

    list<string> extract_file_and_extension(string filename)
    {
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
    bool encode_file(string target_file)
    {
        // split target_file name and extension for output name
        list<string> filename_and_extension = extract_file_and_extension(target_file);
        string filename = filename_and_extension.front();
        string file_extension = filename_and_extension.back();

        auto file_ptr = open_file(target_file);

        // initialize AES and Initialization Vector in Encode function for multiple use
        unsigned char key[32];              // 32 bytes, 256 bits for AES-256
        unsigned char init_vector[16];      // 16 bytes of initialization for 'CBC mode', adds randomization so twin messages are not encrypted equally
        generate_aes_key(key, init_vector); // alike Fernet in Python

        std::vector<unsigned char> encrypted_file = encode_file_with_aes(*file_ptr, key, init_vector);

        bool success = save_encrypted_file(filename + "_encrypted." + file_extension, encrypted_file, init_vector);
        return success;
    };
};

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cout << "Use: main.exe <1 to encrypt, 0 to decrypt > <file> <password (optional)>\n";
        return 1;
    }

    string operation = argv[1];
    string target_file = argv[2];

    if (operation != "1" && operation != "0")
    {
        cout << "Invalid option. Use 1 to encrypt or 0 to decrypt.\n";
        return 1;
    }

    if (target_file.empty())
    {
        cout << "Target file is required.\n";
        return 1;
    }

    if (operation == "1")
    {
        Encoder encoder;
        if (!encoder.encode_file(target_file))
        {
            cerr << "Error encoding file.\n";
            return 1;
        }
        cout << "File encoded successfully.\n";
    }
    else
    {
        Decoder decoder;
        // ask for password
        string password;
        cout << "Enter password: ";
        cin >> password;

        if (!decoder.decode_file(target_file, password))
        {
            cerr << "Error decoding file.\n";
            return 1;
        }
        cout << "File decoded successfully.\n";
    }

    return 0;
};
