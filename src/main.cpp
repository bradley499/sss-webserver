#include "sss/webserver.hpp"

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    /**
     * @brief Flag indicating if the help text should be printed.
     */
    bool show_help = false;

    /**
     * @brief Network port number.
     */
    int server_port = 8080;

    /**
     * @brief Host IP address or hostname.
     */
    std::string server_host = "127.0.0.1";

    /**
     * @brief Path to SSL certificate file.
     */
    std::filesystem::path certificate_path = {};

    /**
     * @brief Path to SSL private key file.
     */
    std::filesystem::path private_key_path = {};

    /**
     * @brief Filesystem path of the directory to serve.
     */
    std::filesystem::path root_directory = {};

    /**
     * @brief Output command line usage instructions to standard output.
     */
    void print_help()
    {
        std::cout << "Usage: sss-webserver [OPTIONS] <DIRECTORY>\n";
        std::cout << "A lightweight embedded HTTP/HTTPS webserver.\n";
        std::cout << "\n";
        std::cout << "Options:\n";
        std::cout << "  -h, --help                  Display this help message and exit\n";
        std::cout << "  -H, --host <IP>             Bind host IP address (default: 127.0.0.1)\n";
        std::cout << "  -p, --port <PORT>           Bind port number (default: 8080)\n";
        std::cout << "  -c, --cert <PATH>           Path to SSL certificate PEM file\n";
        std::cout << "  -k, --key <PATH>            Path to SSL private key PEM file\n";
        std::cout << "  -v, --version               Show the version of the application\n";
        std::cout << "\n";
        std::cout << "Arguments:\n";
        std::cout << "  <DIRECTORY>                 The directory to serve\n";
    }

    /**
     * @brief Parse command line parameters into configuration state.
     * @param argument_count Number of arguments from the operating system.
     * @param argument_values Array of null-terminated argument strings.
     */
    void handle_arguments(int const argument_count, char const *argument_values[])
    {
        std::vector<std::filesystem::path> paths = {};
        for (int argument_index = 1; argument_index < argument_count; ++argument_index)
        {
            std::string const argument = argument_values[argument_index];
            if (argument.length() >= 2 && argument[0] == '-')
            {
                if (argument[1] == '-')
                {
                    if (argument == "--help")
                        show_help = true;
                    else if (argument == "--version")
                    {
                        std::cout << "sss-webserver: v" << SSS_WEBSERVER_VERSION_MAJOR << "."
                                  << SSS_WEBSERVER_VERSION_MINOR << "."
                                  << SSS_WEBSERVER_VERSION_PATCH << "\n";
                        exit(EXIT_SUCCESS);
                    }
                    else if (argument == "--host")
                    {
                        if (++argument_index >= argument_count)
                        {
                            std::cerr << "sss-webserver: Option '--host' requires an argument\n";
                            exit(EXIT_FAILURE);
                        }
                        server_host = argument_values[argument_index];
                    }
                    else if (argument == "--port")
                    {
                        if (++argument_index >= argument_count)
                        {
                            std::cerr << "sss-webserver: Option '--port' requires an argument\n";
                            exit(EXIT_FAILURE);
                        }
                        try
                        {
                            server_port = std::stoi(argument_values[argument_index]);
                        }
                        catch (std::exception const &)
                        {
                            std::cerr << "sss-webserver: Invalid port -- '" << argument_values[argument_index] << "'\n";
                            exit(EXIT_FAILURE);
                        }
                    }
                    else if (argument == "--cert")
                    {
                        if (++argument_index >= argument_count)
                        {
                            std::cerr << "sss-webserver: Option '--cert' requires an argument\n";
                            exit(EXIT_FAILURE);
                        }
                        certificate_path = argument_values[argument_index];
                    }
                    else if (argument == "--key")
                    {
                        if (++argument_index >= argument_count)
                        {
                            std::cerr << "sss-webserver: Option '--key' requires an argument\n";
                            exit(EXIT_FAILURE);
                        }
                        private_key_path = argument_values[argument_index];
                    }
                    else
                    {
                        std::cerr << "sss-webserver: Unrecognized option -- '" << argument << "'\n";
                        exit(EXIT_FAILURE);
                    }
                }
                else
                {
                    for (size_t character_index = 1; character_index < argument.length(); ++character_index)
                    {
                        char const character = argument[character_index];
                        switch (character)
                        {
                        case 'h':
                            show_help = true;
                            break;
                        case 'v':
                            std::cout << "sss-webserver: v" << SSS_WEBSERVER_VERSION_MAJOR << "."
                                      << SSS_WEBSERVER_VERSION_MINOR << "."
                                      << SSS_WEBSERVER_VERSION_PATCH << "\n";
                            exit(EXIT_SUCCESS);
                        case 'H':
                        case 'p':
                        case 'c':
                        case 'k':
                        {
                            std::string value;
                            if (character_index + 1 < argument.length())
                            {
                                value = argument.substr(character_index + 1);
                                character_index = argument.length();
                            }
                            else if (++argument_index < argument_count)
                                value = argument_values[argument_index];
                            else
                            {
                                std::cerr << "sss-webserver: Option '-" << character << "' requires an argument\n";
                                exit(EXIT_FAILURE);
                            }

                            if (character == 'H')
                                server_host = value;
                            else if (character == 'p')
                            {
                                try
                                {
                                    server_port = std::stoi(value);
                                }
                                catch (std::exception const &)
                                {
                                    std::cerr << "sss-webserver: Invalid port -- '" << value << "'\n";
                                    exit(EXIT_FAILURE);
                                }
                            }
                            else if (character == 'c')
                                certificate_path = value;
                            else if (character == 'k')
                                private_key_path = value;
                            break;
                        }
                        default:
                            std::cerr << "sss-webserver: Invalid option -- '" << character << "'\n";
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
            else
                paths.push_back(std::filesystem::path(argument));
        }

        if (show_help)
        {
            print_help();
            exit(EXIT_SUCCESS);
        }
        if (paths.empty())
        {
            std::cerr << "sss-webserver: Too few arguments\n";
            exit(EXIT_FAILURE);
        }
        else if (paths.size() > 1)
        {
            std::cerr << "sss-webserver: Too many arguments\n";
            exit(EXIT_FAILURE);
        }

        if (certificate_path.empty() != private_key_path.empty())
        {
            std::cerr << "sss-webserver: Both -c/--cert and -k/--key must be provided for HTTPS\n";
            exit(EXIT_FAILURE);
        }

        root_directory = paths[0];
    }
} // namespace

int main(int const argument_count, char const *argument_values[])
{
    handle_arguments(argument_count, argument_values);

    try
    {
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        if (pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0)
        {
            std::cerr << "sss-webserver: Failed to set signal mask\n";
            return EXIT_FAILURE;
        }

        sss::webserver::Server const server(root_directory, server_port, server_host, certificate_path, private_key_path);

        bool const is_https = !certificate_path.empty() && !private_key_path.empty();
        if (is_https)
            std::cout << "sss-webserver: Serving '" << root_directory.string() << "' over HTTPS on https://" << server_host << ":" << server_port << "\n";
        else
            std::cout << "sss-webserver: Serving '" << root_directory.string() << "' over HTTP on http://" << server_host << ":" << server_port << "\n";

        int caught_signal = 0;
        sigwait(&signals, &caught_signal);
        return EXIT_SUCCESS;
    }
    catch (std::exception const &exception)
    {
        std::cerr << "sss-webserver: " << exception.what() << "\n";
        return EXIT_FAILURE;
    }
}
