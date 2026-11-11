#pragma once

#include <string>
#include <unordered_map>

namespace sss::webserver
{
    /**
     * @brief Access the global system MIME registry table.
     * @returns Const reference to the MIME mapping table.
     */
    [[nodiscard]] std::unordered_map<std::string, std::string> const &get_system_mime_types();
} // namespace sss::webserver
