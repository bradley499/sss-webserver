#include "sss/webserver.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <httplib.h>

#include "mime_registry.hpp"

namespace
{
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
    };
} // namespace

TEST(MimeRegistryTest, ResolvesSystemMimeTypes)
{
    auto const &mime_types = sss::webserver::get_system_mime_types();
    if (!mime_types.empty())
    {
        auto const html_iterator = mime_types.find("html");
        if (html_iterator != mime_types.end())
            EXPECT_EQ(html_iterator->second, "text/html");
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

    sss::webserver::Options invalid_port_options;
    invalid_port_options.port = 0;
    EXPECT_THROW(sss::webserver::Server("/tmp", invalid_port_options), std::invalid_argument);

    sss::webserver::Options ssl_options;
    ssl_options.certificate_path = "missing_certificate.pem";
    ssl_options.private_key_path = "missing_private_key.pem";
    EXPECT_THROW(sss::webserver::Server("/tmp", ssl_options), std::runtime_error);
}

TEST_F(TemporaryDirectoryFixture, ServesStaticAssets)
{
    this->write_file("index.html", "<h1>Hello World</h1>");
    this->write_file("data.json", "{\"status\":\"ok\"}");
    this->write_file("example/index.html", "<h1>Example Index</h1>");

    int const port = 59123;
    sss::webserver::Options options;
    options.host = "localhost";
    options.port = port;

    sss::webserver::Server const server(this->m_temporary_directory, options);

    httplib::Client client("127.0.0.1", port);

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

TEST_F(TemporaryDirectoryFixture, EnforcesSecurityRestrictions)
{
    this->write_file("index.html", "safe content");
    this->write_file(".env", "SECRET=12345");

    int const port = 59124;
    sss::webserver::Options options;
    options.host = "127.0.0.1";
    options.port = port;

    sss::webserver::Server const server(this->m_temporary_directory, options);

    httplib::Client client("127.0.0.1", port);

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
