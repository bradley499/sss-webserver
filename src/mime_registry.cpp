#include "mime_registry.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace sss::webserver
{
    namespace
    {
        /**
         * @brief Convert an input string to lowercase ASCII characters in place.
         * @param text Input and output text sequence to transform.
         */
        void transform_to_lower(std::string &text) noexcept
        {
            for (char &character : text)
                character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
        }

        /**
         * @brief Parse a MIME type registry file into an extension mapping table.
         * @param file_path Filesystem path to the MIME configuration file.
         * @returns Hash map associating file extensions with MIME content types.
         */
        [[nodiscard]] std::unordered_map<std::string, std::string> load_mime_file(std::filesystem::path const &file_path)
        {
            std::ifstream file_stream(file_path);
            if (!file_stream.is_open())
                return {};

            std::unordered_map<std::string, std::string> mime_map;
            std::string line;

            while (std::getline(file_stream, line))
            {
                auto const comment_position = line.find('#');
                if (comment_position != std::string::npos)
                    line = line.substr(0, comment_position);

                std::istringstream line_stream(line);
                std::string mime_type;
                if (!(line_stream >> mime_type))
                    continue;

                transform_to_lower(mime_type);
                std::string extension;
                while (line_stream >> extension)
                {
                    transform_to_lower(extension);
                    size_t dot_count = 0;
                    while (dot_count < extension.size() && extension[dot_count] == '.')
                        ++dot_count;
                    if (dot_count > 0)
                        extension.erase(0, dot_count);
                    if (!extension.empty())
                        mime_map.emplace(extension, mime_type);
                }
            }

            return mime_map;
        }

    } // namespace

    std::unordered_map<std::string, std::string> const &get_system_mime_types()
    {
        static std::unordered_map<std::string, std::string> const system_mime_types = load_mime_file("/etc/mime.types");
        return system_mime_types;
    }
} // namespace sss::webserver
