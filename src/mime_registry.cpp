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
         * @brief Convert an input string view to lowercase ASCII characters.
         * @param text Input text sequence.
         * @returns New string containing lowercase characters.
         */
        [[nodiscard]] std::string to_lower(std::string_view const text)
        {
            std::string result;
            result.reserve(text.size());
            std::transform(text.begin(), text.end(), std::back_inserter(result), [](unsigned char const character)
            {
                return static_cast<char>(std::tolower(character));
            });
            return result;
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

                mime_type = to_lower(mime_type);
                std::string extension;
                while (line_stream >> extension)
                {
                    extension = to_lower(extension);
                    while (!extension.empty() && extension.front() == '.')
                        extension.erase(0, 1);
                    if (!extension.empty())
                        mime_map.emplace(extension, mime_type);
                }
            }

            return mime_map;
        }

        /**
         * @brief Global system MIME registry loaded at program initialization.
         */
        std::unordered_map<std::string, std::string> const SYSTEM_MIME_TYPES = load_mime_file("/etc/mime.types");
    } // namespace

    std::unordered_map<std::string, std::string> const &get_system_mime_types()
    {
        return SYSTEM_MIME_TYPES;
    }
} // namespace sss::webserver
