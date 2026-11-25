#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#error "CPPHTTPLIB_OPENSSL_SUPPORT must be defined when compiling webserver.cpp"
#endif

#include "sss/webserver.hpp"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

#include <httplib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "mime_registry.hpp"

namespace
{
    /**
     * @brief Success return code from OpenSSL configuration calls.
     */
    constexpr int SSL_SUCCESS = 1;

    /**
     * @brief Minimum valid TCP port number.
     */
    constexpr int MINIMUM_PORT = 1;

    /**
     * @brief Maximum valid TCP port number.
     */
    constexpr int MAXIMUM_PORT = 65535;

    /**
     * @brief Socket option value to enable address reuse.
     */
    constexpr int ENABLE_SOCKET_OPTION = 1;

    /**
     * @brief Read timeout in seconds.
     */
    constexpr time_t READ_TIMEOUT_SECONDS = 5;

    /**
     * @brief Write timeout in seconds.
     */
    constexpr time_t WRITE_TIMEOUT_SECONDS = 10;

    /**
     * @brief Sub-second microsecond timeout component.
     */
    constexpr time_t TIMEOUT_MICROSECONDS = 0;

    /**
     * @brief Maximum number of worker threads allocated for the thread pool task queue.
     */
    constexpr size_t MAXIMUM_WORKER_THREADS = 8;

    /**
     * @brief Check whether a request path attempts path traversal through parent directories.
     * @param path_string Input path string to evaluate.
     * @returns True if path traversal sequence exists.
     */
    [[nodiscard]] bool contains_path_traversal(std::string const &path_string)
    {
        std::string normalized_path = httplib::detail::decode_url(path_string, false);
        std::replace(normalized_path.begin(), normalized_path.end(), '\\', '/');
        std::filesystem::path const filesystem_path(normalized_path);
        for (auto const &element : filesystem_path)
            if (element.string() == "..")
                return true;
        if (normalized_path == ".." || normalized_path.rfind("../", 0) == 0 || normalized_path.find("/../") != std::string::npos || (normalized_path.length() >= 3 && normalized_path.rfind("/..") == normalized_path.length() - 3))
            return true;
        return false;
    }

    /**
     * @brief Check if any path segment begins with a dot character.
     * @param path_string Input path string to evaluate.
     * @returns True if any segment starts with a dot.
     */
    [[nodiscard]] bool contains_dotfile_segment(std::string const &path_string)
    {
        std::string normalized_path = httplib::detail::decode_url(path_string, false);
        std::replace(normalized_path.begin(), normalized_path.end(), '\\', '/');
        std::filesystem::path const filesystem_path(normalized_path);
        for (auto const &element : filesystem_path)
        {
            auto const element_string = element.string();
            if (!element_string.empty() && element_string != "/" && element_string != "." && element_string != ".." && element_string.front() == '.')
                return true;
        }
        return false;
    }

    /**
     * @brief Check whether an incoming request contains prohibited null bytes.
     * @param request Received HTTP request structure.
     * @returns True if null bytes or percent-encoded null bytes exist.
     */
    [[nodiscard]] bool contains_null_byte(httplib::Request const &request)
    {
        return (request.path.find('\0') != std::string::npos || request.target.find('\0') != std::string::npos || request.target.find("%00") != std::string::npos || request.path.find("%00") != std::string::npos);
    }

    /**
     * @brief Validate that the given port is within the valid TCP range.
     * @param port Network port to check.
     * @returns Port number cast to 16-bit unsigned integer.
     * @throws std::invalid_argument If port is outside 1 to 65535.
     */
    [[nodiscard]] uint16_t validate_port(int const port)
    {
        if (port < MINIMUM_PORT || port > MAXIMUM_PORT)
            throw std::invalid_argument("Port must be between " + std::to_string(MINIMUM_PORT) + " and " + std::to_string(MAXIMUM_PORT) + ": " + std::to_string(port));
        return static_cast<uint16_t>(port);
    }

    /**
     * @brief Resolve a bind host string to a deterministic IP address without DNS lookups.
     * @param host Input host string.
     * @returns Normalized IP address string.
     */
    [[nodiscard]] std::string normalize_bind_host(std::string const &host)
    {
        if (host == "localhost")
            return "127.0.0.1";
        return host;
    }

    /**
     * @brief Canonicalize and validate that the target directory exists.
     * @param root_directory Input directory path.
     * @returns Weakly canonicalized path string.
     * @throws std::runtime_error If path does not exist or is not a directory.
     */
    [[nodiscard]] std::string resolve_root_path(std::filesystem::path const &root_directory)
    {
        std::error_code error_code;
        auto const canonical_root = std::filesystem::weakly_canonical(root_directory, error_code);
        if (error_code || !std::filesystem::exists(canonical_root))
            throw std::runtime_error("Root directory does not exist: " + root_directory.string());
        if (!std::filesystem::is_directory(canonical_root))
            throw std::runtime_error("Root path is not a directory: " + root_directory.string());
        return canonical_root.string();
    }

    /**
     * @brief Validate SSL files and create an httplib SSLServer instance.
     * @param certificate_path Path to certificate file in PEM format.
     * @param private_key_path Path to private key file in PEM format.
     * @returns Unique pointer to configured httplib Server.
     * @throws std::runtime_error If certificate verification fails.
     */
    [[nodiscard]] std::unique_ptr<httplib::Server> create_ssl_server(std::filesystem::path const &certificate_path, std::filesystem::path const &private_key_path)
    {
        if (!std::filesystem::exists(certificate_path))
            throw std::runtime_error("Certificate file does not exist: " + certificate_path.string());
        if (!std::filesystem::is_regular_file(certificate_path))
            throw std::runtime_error("Certificate path is not a regular file: " + certificate_path.string());
        if (!std::filesystem::exists(private_key_path))
            throw std::runtime_error("Private key file does not exist: " + private_key_path.string());
        if (!std::filesystem::is_regular_file(private_key_path))
            throw std::runtime_error("Private key path is not a regular file: " + private_key_path.string());

        std::string configuration_error;
        auto ssl_server = std::make_unique<httplib::SSLServer>(
            [&](SSL_CTX &ssl_context)
            {
                ERR_clear_error();
                if (SSL_CTX_use_certificate_chain_file(&ssl_context, certificate_path.c_str()) != SSL_SUCCESS)
                {
                    configuration_error = "Failed to load certificate file: " + certificate_path.string();
                    ERR_clear_error();
                    return false;
                }

                if (SSL_CTX_use_PrivateKey_file(&ssl_context, private_key_path.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS)
                {
                    unsigned long const error_code = ERR_peek_last_error();
                    if (ERR_GET_REASON(error_code) == X509_R_KEY_VALUES_MISMATCH)
                        configuration_error = "Private key does not match certificate: " + private_key_path.string();
                    else
                        configuration_error = "Failed to load private key file: " + private_key_path.string();
                    ERR_clear_error();
                    return false;
                }

                if (SSL_CTX_check_private_key(&ssl_context) != SSL_SUCCESS)
                {
                    configuration_error = "Private key does not match certificate: " + private_key_path.string();
                    ERR_clear_error();
                    return false;
                }

                ERR_clear_error();
                return true;
            });

        if (!configuration_error.empty())
            throw std::runtime_error(configuration_error);

        if (!ssl_server->is_valid())
            throw std::runtime_error("SSL server initialization failed");

        return ssl_server;
    }

    /**
     * @brief Allocate a server instance based on certificate paths.
     * @param certificate_path Path to certificate file.
     * @param private_key_path Path to private key file.
     * @returns Unique pointer to allocated httplib Server.
     * @throws std::runtime_error If certificate configuration is mismatched.
     */
    [[nodiscard]] std::unique_ptr<httplib::Server> create_server_instance(std::filesystem::path const &certificate_path, std::filesystem::path const &private_key_path)
    {
        if (certificate_path.empty() != private_key_path.empty())
            throw std::runtime_error("Both certificate_path and private_key_path must be provided for HTTPS");
        else if (!certificate_path.empty() && !private_key_path.empty())
            return create_ssl_server(certificate_path, private_key_path);
        return std::make_unique<httplib::Server>();
    }

    /**
     * @brief Generate default security and identification headers for HTTP responses.
     * @param is_secure Flag indicating if connection is secured with TLS encryption.
     * @returns Headers map containing security and identification key-value pairs.
     */
    [[nodiscard]] httplib::Headers create_default_headers(bool const is_secure)
    {
        httplib::Headers headers = {{"Server", "SSS"}, {"X-Content-Type-Options", "nosniff"}, {"X-Frame-Options", "SAMEORIGIN"}};
        if (is_secure)
            headers.emplace("Strict-Transport-Security", "max-age=3600; includeSubDomains");
        return headers;
    }
} // namespace

namespace sss::webserver
{
    Server::Server(std::filesystem::path const &root_directory, int const port, std::string const &host, std::filesystem::path const &certificate_path, std::filesystem::path const &private_key_path)
        : m_server(create_server_instance(certificate_path, private_key_path)),
          m_worker_thread()
    {
        std::string const root_path = resolve_root_path(root_directory);
        uint16_t const valid_port = validate_port(port);
        std::string const bind_host = normalize_bind_host(host);

        this->m_server->new_task_queue = []()
        {
            return new httplib::ThreadPool(MAXIMUM_WORKER_THREADS);
        };

        this->m_server->set_socket_options(
            [](auto const socket_descriptor)
            {
                int const socket_option = ENABLE_SOCKET_OPTION;
                setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void const *>(&socket_option), sizeof(socket_option));
            });

        this->m_server->set_read_timeout(READ_TIMEOUT_SECONDS, TIMEOUT_MICROSECONDS);
        this->m_server->set_write_timeout(WRITE_TIMEOUT_SECONDS, TIMEOUT_MICROSECONDS);

        for (auto const &[extension, mime_type] : get_system_mime_types())
            this->m_server->set_file_extension_and_mimetype_mapping(extension, mime_type);

        bool const is_secure = (!certificate_path.empty() && !private_key_path.empty());
        httplib::Headers const default_headers = create_default_headers(is_secure);

        this->m_server->set_pre_routing_handler(
            [default_headers](httplib::Request const &request, httplib::Response &response)
            {
                for (auto const &[header_name, header_value] : default_headers)
                    response.set_header(header_name, header_value);

                if (contains_null_byte(request))
                {
                    response.status = httplib::StatusCode::BadRequest_400;
                    response.set_content("Bad Request", "text/plain");
                    return httplib::Server::HandlerResponse::Handled;
                }

                if (request.method != "GET" && request.method != "HEAD")
                {
                    response.status = httplib::StatusCode::MethodNotAllowed_405;
                    response.set_header("Allow", "GET, HEAD");
                    response.set_content("Method Not Allowed", "text/plain");
                    return httplib::Server::HandlerResponse::Handled;
                }

                if (contains_path_traversal(request.path) || contains_path_traversal(request.target))
                {
                    response.status = httplib::StatusCode::Forbidden_403;
                    response.set_content("Forbidden", "text/plain");
                    return httplib::Server::HandlerResponse::Handled;
                }

                if (contains_dotfile_segment(request.path) || contains_dotfile_segment(request.target))
                {
                    response.status = httplib::StatusCode::Forbidden_403;
                    response.set_content("Forbidden", "text/plain");
                    return httplib::Server::HandlerResponse::Handled;
                }

                return httplib::Server::HandlerResponse::Unhandled;
            });

        this->m_server->set_mount_point("/", root_path, default_headers);

        if (!this->m_server->bind_to_port(bind_host, valid_port))
            throw std::runtime_error("Failed to bind socket on " + bind_host + ":" + std::to_string(valid_port));

        this->m_worker_thread = std::thread([this]()
        {
            this->m_server->listen_after_bind();
        });

        this->m_server->wait_until_ready();
        if (!this->m_server->is_running())
        {
            if (this->m_worker_thread.joinable())
            {
                this->m_server->stop();
                this->m_worker_thread.join();
            }
            throw std::runtime_error("Server failed to start listening on " + bind_host + ":" + std::to_string(valid_port));
        }
    }

    Server::~Server()
    {
        if (this->m_server)
        {
            this->m_server->stop();
            this->m_server->decommission();
        }
        if (this->m_worker_thread.joinable())
            this->m_worker_thread.join();
    }
} // namespace sss::webserver
