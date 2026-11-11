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
     * @brief Embedded HTTP and HTTPS webserver running on a background thread.
     */
    class Server final
    {
    public:
        /**
         * @brief Construct an embedded webserver instance.
         * @param root_directory Local filesystem path to serve.
         * @param port Network port number. Must be between 1 and 65535.
         * @param host Host IP address or hostname for socket binding.
         * @param certificate_path Optional path to certificate file in PEM format for TLS encryption.
         * @param private_key_path Optional path to private key file in PEM format for TLS encryption.
         * @throws std::invalid_argument If the port number is invalid.
         * @throws std::runtime_error If paths are invalid or socket binding fails.
         */
        explicit Server(std::filesystem::path const &root_directory,
                        int const port = 8080,
                        std::string const &host = "127.0.0.1",
                        std::filesystem::path const &certificate_path = {},
                        std::filesystem::path const &private_key_path = {});

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
