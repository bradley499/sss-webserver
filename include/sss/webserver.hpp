#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <thread>

namespace httplib
{
    class Server;
} // namespace httplib

namespace sss::webserver
{
    /**
     * @brief Configuration options for network socket binding and security.
     */
    struct Options
    {
        /**
         * @brief Host IP address for network binding.
         */
        std::string host = "127.0.0.1";

        /**
         * @brief Network port number. Must be between 1 and 65535.
         */
        int port = 8080;

        /**
         * @brief Optional path to certificate file in PEM format for TLS encryption.
         */
        std::filesystem::path certificate_path{};

        /**
         * @brief Optional path to private key file in PEM format for TLS encryption.
         */
        std::filesystem::path private_key_path{};
    };

    /**
     * @brief Embedded HTTP and HTTPS webserver running on a background thread.
     */
    class Server final
    {
    public:
        /**
         * @brief Construct a Server instance using filesystem and network options.
         * @param root_directory Local filesystem path to serve.
         * @param options Network and TLS configuration options.
         * @throws std::invalid_argument If the port number is invalid.
         * @throws std::runtime_error If paths are invalid or socket binding fails.
         */
        explicit Server(std::filesystem::path const &root_directory,
                        Options const &options = Options{});

        /**
         * @brief Destroy the Server instance and stop listener thread.
         */
        ~Server();

        Server(Server const &) = delete;
        Server &operator=(Server const &) = delete;
        Server(Server &&) = delete;
        Server &operator=(Server &&) = delete;

    private:
        /**
         * @brief Underlying httplib server instance.
         */
        std::unique_ptr<httplib::Server> m_server;

        /**
         * @brief Background accept loop worker thread.
         */
        std::thread m_worker_thread;
    };
} // namespace sss::webserver
