#include "sss/webserver.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "mime_registry.hpp"

namespace
{
    /**
     * @brief Default network port for testing validation failure cases.
     */
    constexpr int DEFAULT_VALIDATION_PORT = 8080;

    /**
     * @brief Invalid network port for validation checks.
     */
    constexpr int INVALID_PORT = 0;

    /**
     * @brief Dedicated port for static assets test suite.
     */
    constexpr int STATIC_ASSETS_TEST_PORT = 59123;

    /**
     * @brief Dedicated port for security restrictions test suite.
     */
    constexpr int SECURITY_RESTRICTIONS_TEST_PORT = 59124;

    /**
     * @brief Dedicated port for TLS encrypted assets test suite.
     */
    constexpr int TLS_ASSETS_TEST_PORT = 59125;

    /**
     * @brief Custom deleter for OpenSSL EVP_PKEY structures.
     */
    struct KeyDeleter
    {
        /**
         * @brief Free the EVP_PKEY memory.
         * @param key_pointer Pointer to EVP_PKEY structure to free.
         */
        void operator()(EVP_PKEY *key_pointer) const
        {
            if (key_pointer != nullptr)
                EVP_PKEY_free(key_pointer);
        }
    };

    /**
     * @brief Custom deleter for OpenSSL X509 structures.
     */
    struct CertificateDeleter
    {
        /**
         * @brief Free the X509 certificate memory.
         * @param certificate_pointer Pointer to X509 certificate structure to free.
         */
        void operator()(X509 *certificate_pointer) const
        {
            if (certificate_pointer != nullptr)
                X509_free(certificate_pointer);
        }
    };

    /**
     * @brief Custom deleter for standard C FILE pointers.
     */
    struct FileDeleter
    {
        /**
         * @brief Close the file handle.
         * @param file_handle Pointer to FILE handle to close.
         */
        void operator()(FILE *file_handle) const
        {
            if (file_handle != nullptr)
                fclose(file_handle);
        }
    };

    /**
     * @brief Test fixture providing a clean temporary directory for filesystem operations.
     */
    class TemporaryDirectoryFixture : public ::testing::Test
    {
    protected:
        /**
         * @brief Isolated filesystem path for file serving tests.
         */
        std::filesystem::path m_temporary_directory;

        /**
         * @brief Set up temporary directory on disk.
         */
        void SetUp() override
        {
            static std::atomic<uint64_t> identifier_counter{0};
            auto const current_identifier = ++identifier_counter;
            this->m_temporary_directory = (std::filesystem::temp_directory_path() / ("sss_test_" + std::to_string(current_identifier)));
            std::filesystem::create_directories(this->m_temporary_directory);
        }

        /**
         * @brief Remove temporary directory from disk.
         */
        void TearDown() override
        {
            std::error_code error_code;
            std::filesystem::remove_all(this->m_temporary_directory, error_code);
        }

        /**
         * @brief Create a file with contents inside the temporary directory.
         * @param relative_path Path relative to temporary directory.
         * @param content String data to write into the file.
         */
        void write_file(std::string const &relative_path, std::string const &content)
        {
            auto const full_path = (this->m_temporary_directory / relative_path);
            std::filesystem::create_directories(full_path.parent_path());
            std::ofstream output_file_stream(full_path, std::ios::binary);
            output_file_stream << content;
        }

        /**
         * @brief Generate a self-signed RSA certificate and private key in PEM format.
         * @param certificate_path Destination filesystem path for the certificate PEM file.
         * @param private_key_path Destination filesystem path for the private key PEM file.
         */
        void generate_self_signed_certificate(std::filesystem::path const &certificate_path,
                                              std::filesystem::path const &private_key_path)
        {
            constexpr int rsa_key_length = 2048;
            constexpr long certificate_serial_number = 1L;
            constexpr long certificate_validity_seconds = 31536000L;
            constexpr long certificate_time_adjustment_seconds = 0L;
            constexpr int null_terminated_length = -1;
            constexpr int append_entry = -1;
            constexpr unsigned long no_entry_flags = 0L;

            std::unique_ptr<EVP_PKEY, KeyDeleter> const private_key(EVP_RSA_gen(rsa_key_length));
            if (!private_key)
                throw std::runtime_error("Failed to generate RSA private key");

            std::unique_ptr<X509, CertificateDeleter> const certificate(X509_new());
            if (!certificate)
                throw std::runtime_error("Failed to allocate X509 certificate");

            ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), certificate_serial_number);
            X509_gmtime_adj(X509_get_notBefore(certificate.get()), certificate_time_adjustment_seconds);
            X509_gmtime_adj(X509_get_notAfter(certificate.get()), certificate_validity_seconds);
            X509_set_pubkey(certificate.get(), private_key.get());

            X509_NAME *name = X509_get_subject_name(certificate.get());
            X509_NAME_add_entry_by_txt(name,
                                       "CN",
                                       MBSTRING_ASC,
                                       reinterpret_cast<unsigned char const *>("localhost"),
                                       null_terminated_length,
                                       append_entry,
                                       no_entry_flags);
            X509_set_issuer_name(certificate.get(), name);

            if (X509_sign(certificate.get(), private_key.get(), EVP_sha256()) == 0)
                throw std::runtime_error("Failed to sign X509 certificate");

            std::unique_ptr<FILE, FileDeleter> const key_file(fopen(private_key_path.c_str(), "wb"));
            if (!key_file)
                throw std::runtime_error("Failed to open private key file for writing: " + private_key_path.string());
            if (PEM_write_PrivateKey(key_file.get(), private_key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 0)
                throw std::runtime_error("Failed to write PEM private key");

            std::unique_ptr<FILE, FileDeleter> const certificate_file(fopen(certificate_path.c_str(), "wb"));
            if (!certificate_file)
                throw std::runtime_error("Failed to open certificate file for writing: " + certificate_path.string());
            if (PEM_write_X509(certificate_file.get(), certificate.get()) == 0)
                throw std::runtime_error("Failed to write PEM certificate");
        }
    };
} // namespace

TEST(MimeRegistryTest, ResolvesSystemMimeTypes)
{
    auto const &mime_types = sss::webserver::get_system_mime_types();
    if (!mime_types.empty())
    {
        auto const html_iterator = mime_types.find("html");
        if (html_iterator != mime_types.end())
        {
            EXPECT_EQ(html_iterator->second, "text/html");
        }
    }
}

TEST(ServerConfigurationTest, RejectsInvalidInputs)
{
    try
    {
        sss::webserver::Server const server("/nonexistent_directory_path_12345");
        FAIL() << "Expected std::runtime_error for nonexistent directory";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("does not exist"), std::string::npos);
    }

    try
    {
        sss::webserver::Server const server("/etc/hosts");
        FAIL() << "Expected std::runtime_error for file path instead of directory";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("not a directory"), std::string::npos);
    }

    EXPECT_THROW(sss::webserver::Server("/tmp", INVALID_PORT), std::invalid_argument);
}

TEST_F(TemporaryDirectoryFixture, RejectsInvalidTlsConfiguration)
{
    // Mismatched configuration: certificate path specified without private key path
    EXPECT_THROW(sss::webserver::Server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", "certificate.pem", ""), std::runtime_error);

    // Mismatched configuration: private key path specified without certificate path
    EXPECT_THROW(sss::webserver::Server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", "", "private_key.pem"), std::runtime_error);

    // Nonexistent certificate file
    auto const missing_certificate_path = (this->m_temporary_directory / "missing_certificate.pem");
    auto const missing_private_key_path = (this->m_temporary_directory / "missing_private_key.pem");
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", missing_certificate_path, missing_private_key_path);
        FAIL() << "Expected std::runtime_error for nonexistent certificate file";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Certificate file does not exist"), std::string::npos);
    }

    // Certificate path is a directory instead of a regular file
    auto const certificate_directory_path = (this->m_temporary_directory / "certificate_directory");
    std::filesystem::create_directories(certificate_directory_path);
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", certificate_directory_path, missing_private_key_path);
        FAIL() << "Expected std::runtime_error for directory certificate path";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Certificate path is not a regular file"), std::string::npos);
    }

    // Generate a valid certificate and private key pair for remaining validation tests
    auto const valid_certificate_path = (this->m_temporary_directory / "valid_certificate.pem");
    auto const valid_private_key_path = (this->m_temporary_directory / "valid_private_key.pem");
    this->generate_self_signed_certificate(valid_certificate_path, valid_private_key_path);

    // Nonexistent private key file when certificate file exists
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", valid_certificate_path, missing_private_key_path);
        FAIL() << "Expected std::runtime_error for nonexistent private key file";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Private key file does not exist"), std::string::npos);
    }

    // Private key path is a directory instead of a regular file
    auto const private_key_directory_path = (this->m_temporary_directory / "private_key_directory");
    std::filesystem::create_directories(private_key_directory_path);
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", valid_certificate_path, private_key_directory_path);
        FAIL() << "Expected std::runtime_error for directory private key path";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Private key path is not a regular file"), std::string::npos);
    }

    // Corrupted certificate file content
    auto const corrupt_certificate_path = (this->m_temporary_directory / "corrupt_certificate.pem");
    this->write_file("corrupt_certificate.pem", "CORRUPTED CERTIFICATE CONTENT");
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", corrupt_certificate_path, valid_private_key_path);
        FAIL() << "Expected std::runtime_error for corrupted certificate file";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Failed to load certificate file"), std::string::npos);
    }

    // Corrupted private key file content
    auto const corrupt_private_key_path = (this->m_temporary_directory / "corrupt_private_key.pem");
    this->write_file("corrupt_private_key.pem", "CORRUPTED PRIVATE KEY CONTENT");
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", valid_certificate_path, corrupt_private_key_path);
        FAIL() << "Expected std::runtime_error for corrupted private key file";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Failed to load private key file"), std::string::npos);
    }

    // Mismatched certificate and private key (generated from different key pairs)
    auto const second_certificate_path = (this->m_temporary_directory / "second_certificate.pem");
    auto const second_private_key_path = (this->m_temporary_directory / "second_private_key.pem");
    this->generate_self_signed_certificate(second_certificate_path, second_private_key_path);
    try
    {
        sss::webserver::Server const server(this->m_temporary_directory, DEFAULT_VALIDATION_PORT, "127.0.0.1", valid_certificate_path, second_private_key_path);
        FAIL() << "Expected std::runtime_error for mismatched certificate and private key";
    }
    catch (std::runtime_error const &exception)
    {
        EXPECT_NE(std::string(exception.what()).find("Private key does not match certificate"), std::string::npos);
    }
}

TEST_F(TemporaryDirectoryFixture, ServesStaticAssets)
{
    this->write_file("index.html", "<h1>Hello World</h1>");
    this->write_file("data.json", "{\"status\":\"ok\"}");
    this->write_file("example/index.html", "<h1>Example Index</h1>");

    sss::webserver::Server const server(this->m_temporary_directory, STATIC_ASSETS_TEST_PORT, "localhost");

    httplib::Client client("127.0.0.1", STATIC_ASSETS_TEST_PORT);

    auto const root_response = client.Get("/");
    ASSERT_TRUE(root_response);
    EXPECT_EQ(root_response->status, httplib::StatusCode::OK_200);
    EXPECT_EQ(root_response->get_header_value("Server"), "SSS");
    EXPECT_EQ(root_response->get_header_value("Content-Type"), "text/html");
    EXPECT_EQ(root_response->body, "<h1>Hello World</h1>");

    auto const asset_response = client.Get("/data.json");
    ASSERT_TRUE(asset_response);
    EXPECT_EQ(asset_response->status, httplib::StatusCode::OK_200);
    EXPECT_EQ(asset_response->get_header_value("Content-Type"), "application/json");
    EXPECT_EQ(asset_response->body, "{\"status\":\"ok\"}");

    auto const example_slash_response = client.Get("/example/");
    ASSERT_TRUE(example_slash_response);
    EXPECT_EQ(example_slash_response->status, httplib::StatusCode::OK_200);
    EXPECT_EQ(example_slash_response->body, "<h1>Example Index</h1>");

    auto const example_redirect_response = client.Get("/example");
    ASSERT_TRUE(example_redirect_response);
    EXPECT_EQ(example_redirect_response->status, httplib::StatusCode::MovedPermanently_301);
    EXPECT_EQ(example_redirect_response->get_header_value("Location"), "/example/");

    auto const missing_response = client.Get("/missing.html");
    ASSERT_TRUE(missing_response);
    EXPECT_EQ(missing_response->status, httplib::StatusCode::NotFound_404);
}

TEST_F(TemporaryDirectoryFixture, ServesStaticAssetsOverHttps)
{
    this->write_file("index.html", "<h1>Secure SSS</h1>");

    auto const certificate_path = (this->m_temporary_directory / "certificate.pem");
    auto const private_key_path = (this->m_temporary_directory / "private_key.pem");
    this->generate_self_signed_certificate(certificate_path, private_key_path);

    sss::webserver::Server const server(this->m_temporary_directory, TLS_ASSETS_TEST_PORT, "127.0.0.1", certificate_path, private_key_path);

    httplib::SSLClient client("127.0.0.1", TLS_ASSETS_TEST_PORT);
    client.enable_server_certificate_verification(false);

    auto const response = client.Get("/index.html");
    ASSERT_TRUE(response);
    EXPECT_EQ(response->status, httplib::StatusCode::OK_200);
    EXPECT_EQ(response->get_header_value("Server"), "SSS");
    EXPECT_EQ(response->get_header_value("Content-Type"), "text/html");
    EXPECT_EQ(response->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(response->get_header_value("X-Frame-Options"), "SAMEORIGIN");
    EXPECT_EQ(response->body, "<h1>Secure SSS</h1>");
}

TEST_F(TemporaryDirectoryFixture, EnforcesSecurityRestrictions)
{
    this->write_file("index.html", "safe content");
    this->write_file(".env", "SECRET=12345");

    sss::webserver::Server const server(this->m_temporary_directory, SECURITY_RESTRICTIONS_TEST_PORT);

    httplib::Client client("127.0.0.1", SECURITY_RESTRICTIONS_TEST_PORT);

    auto const traversal_response = client.Get("/../outside.txt");
    ASSERT_TRUE(traversal_response);
    EXPECT_EQ(traversal_response->status, httplib::StatusCode::Forbidden_403);

    auto const dotfile_response = client.Get("/.env");
    ASSERT_TRUE(dotfile_response);
    EXPECT_EQ(dotfile_response->status, httplib::StatusCode::Forbidden_403);

    auto const normal_response = client.Get("/index.html");
    ASSERT_TRUE(normal_response);
    EXPECT_EQ(normal_response->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(normal_response->get_header_value("X-Frame-Options"), "SAMEORIGIN");
}
